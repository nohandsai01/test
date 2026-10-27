'use strict';
// G41 source-only, local synthetic journals; no production scope or credentials.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {createGuardianLocalOperatorSession}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const {createGuardianLocalReceiptJournal,generationLedgerName}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const {createGuardianOfflineCasework}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-casework.cjs');
const {createGuardianCaseworkDiagnostics}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-casework-diagnostics.cjs');
const {makeBundle}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs');

const worker=path.join(__dirname,'guardian-protected-worker-child.cjs');
const stopped={state:'STOPPED',errorCode:null,hostStopped:true,
  activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false};
const failed={state:'FAILED',errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',
  hostStopped:false,activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false};
const hash=(data)=>crypto.createHash('sha256').update(data).digest('hex');
function claimed(fields) {
  const {claimSha256:ignored,...pins}=fields;
  const claim={schemaVersion:2,
    kind:'GUARDIAN_CASEWORK_GENERATION_CLAIM_V2',...pins};
  return Object.freeze({...claim,claimSha256:hash(JSON.stringify(claim))});
}
// G42: hash the verifier's *selectedFailure* content in its fixed V2
// event-field order; not the outer packet, receipt, or claimant field order.
function eventContentDigest(event) {
  return hash(JSON.stringify({
    eventId:event.eventId,timestamp:event.timestamp,state:event.state,
    errorCode:event.errorCode,generationId:event.generationId,
  }));
}
function contentClaim(base,terminalEventSha256) {
  const pinned={
    schemaVersion:2,kind:'GUARDIAN_CASEWORK_GENERATION_CLAIM_V2',
    caseworkReceiptId:base.caseworkReceiptId,
    bundleSha256:base.bundleSha256,
    caseworkJournalSha256:base.caseworkJournalSha256,
    terminalEventId:base.terminalEventId,terminalEventSha256,
    generationId:base.generationId,
    terminalJournalSha256:base.terminalJournalSha256,
    launchLedgerSha256:base.launchLedgerSha256,
  };
  return Object.freeze({...pinned,claimSha256:hash(JSON.stringify(pinned))});
}
function hold(out,verified) {
  assert.equal(out.schemaVersion,2);
  assert.equal(out.kind,'GUARDIAN_CASEWORK_GENERATION_PIN_ASSESSMENT_V2');
  assert.equal(out.status,'SOURCE_ONLY_HOLD');
  assert.equal(out.authority,'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(out.custodyVerified,false);
  assert.equal(out.liveness,'NOT_PROVEN');
  assert.equal(out.automaticRestartAllowed,false);
  assert.equal(out.activationAllowed,false);
  assert.equal(out.releaseAuthority,'NOT_ISSUED');
  assert.equal(out.manualInterventionRequired,true);
  assert.equal(Object.isFrozen(out),true);
  if (!verified) {
    assert.equal(out.priority,'P0');
    assert.equal(out.classification,'NOT_VERIFIED');
    assert.equal(out.claimSha256,null);
    assert.equal(out.crossJournalBinding,'NOT_PROVEN');
    assert.equal(out.generationLedgerBinding,'NOT_PROVEN');
  } else {
    assert.equal(out.priority,'P1');
    assert.equal(out.classification,
      'LOCAL_UNTRUSTED_MANIFEST_PINS_MATCH_ONLY');
    assert.equal(out.crossJournalBinding,
      'LOCAL_UNAUTHENTICATED_PIN_MATCH_ONLY');
    assert.equal(out.generationLedgerBinding,
      'LOCAL_V2_FAULT_AND_LEDGER_MATCH_ONLY');
  }
  for(const forbidden of ['rawBundle','journalPath','pid','privateKey','token',
    'secret','start','stop','clearHold','publishCheck','writeD1']) {
    assert.equal(Object.hasOwn(out,forbidden),false);
  }
}
async function fixture(fn) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-g41-'));
  const source=path.join(root,'source'), cases=path.join(root,'casework');
  fs.mkdirSync(source,{mode:0o700});
  fs.mkdirSync(cases,{mode:0o700});
  const fileName='guardian-g41-source.jsonl';
  const caseFile='guardian-g41-casework.jsonl';
  const journal=createGuardianLocalReceiptJournal({directory:source,fileName});
  const session=createGuardianLocalOperatorSession({
    cwd:path.dirname(worker),entrypoint:worker,directory:source,fileName,
    caseworkDirectory:cases,caseworkFileName:caseFile,
  });
  const casework=createGuardianOfflineCasework({
    directory:cases,fileName:caseFile,
  });
  const inspector=()=>createGuardianCaseworkDiagnostics({
    directory:cases,fileName:caseFile,
  });
  // Build real, locally consistent V1 bundle history, then a separately
  // persisted generation-bound V2 failure. These do NOT prove causality.
  journal.append(stopped);
  const before=session.operator.captureOfflineIncidentBrief();
  journal.append(failed);
  const after=session.operator.captureOfflineIncidentBrief();
  const raw=JSON.stringify(makeBundle([before,after]));
  const intake=casework.intakeMany([raw]).entries[0];
  assert.equal(intake.decision,'QUARANTINED');
  const generationId=crypto.randomBytes(16).toString('hex');
  journal.recordLaunch({generationId,activationAllowed:false,
    releaseAuthority:'NOT_ISSUED'});
  journal.append({...failed,generationId});
  const terminalPath=path.join(source,fileName);
  const casePath=path.join(cases,caseFile);
  const ledgerPath=path.join(source,generationLedgerName(fileName));
  const rows=fs.readFileSync(terminalPath,'utf8').trim().split('\n')
    .map(JSON.parse);
  const terminal=rows.at(-1);
  assert.equal(terminal.generationId,generationId);
  const claim=claimed({
    caseworkReceiptId:intake.id,bundleSha256:intake.bundleSha256,
    caseworkJournalSha256:inspector().inspect().journalSha256,
    terminalEventId:terminal.eventId,generationId,
    terminalJournalSha256:hash(fs.readFileSync(terminalPath)),
    launchLedgerSha256:hash(fs.readFileSync(ledgerPath)),
  });
  try {
    await fn({root,source,cases,terminalPath,casePath,ledgerPath,
      journal,session,casework,inspector,intake,claim,terminal,raw});
  } finally {fs.rmSync(root,{recursive:true,force:true});}
}

test('G41 opt-in Operator pins real quarantined Casework receipt and V2 fault locally, always HOLD',async()=>{
  await fixture(async f=>{
    const baseline=Object.freeze({cwd:path.dirname(worker),entrypoint:worker,
      directory:f.source,fileName:'guardian-g41-source.jsonl'});
    const without=createGuardianLocalOperatorSession(baseline);
    assert.equal(Object.hasOwn(without.operator,
      'assessCaseworkGenerationPin'),false);
    assert.equal(typeof f.session.operator.assessCaseworkGenerationPin,
      'function');
    const before=[fs.readFileSync(f.terminalPath),
      fs.readFileSync(f.casePath),fs.readFileSync(f.ledgerPath)];
    const correlated=f.session.operator.assessCaseworkGenerationEvidence();
    assert.equal(correlated.classification,
      'LOCAL_COINCIDENT_OBSERVATIONS_ONLY');
    const received=f.inspector().inspectQuarantinedReceipt({
      receiptId:f.claim.caseworkReceiptId,
      journalSha256:f.claim.caseworkJournalSha256,
    });
    assert.equal(received.result,'LOCAL_QUARANTINE_OBSERVED_ONLY');
    assert.equal(received.bundleSha256,f.claim.bundleSha256);
    assert.equal(received.custodyVerified,false);
    const result=f.session.operator.assessCaseworkGenerationPin(f.claim);
    hold(result,true);
    assert.equal(result.claimSha256,f.claim.claimSha256);
    assert.equal(result.caseworkJournalSha256,f.claim.caseworkJournalSha256);
    assert.equal(result.terminalJournalSha256,f.claim.terminalJournalSha256);
    assert.equal(result.launchLedgerSha256,f.claim.launchLedgerSha256);
    assert.deepEqual([fs.readFileSync(f.terminalPath),
      fs.readFileSync(f.casePath),fs.readFileSync(f.ledgerPath)],before);
    assert.equal(Object.isFrozen(f.session.operator),true);
  });
});

test('G41 rejects malformed, accessor, forged, mismatched and digest-recomputed claims',async()=>{
  await fixture(async f=>{
    const result=f.session.operator.assessCaseworkGenerationPin;
    const bad=[
      null,{},f.claim.claimSha256,
      {...f.claim,token:'SECRET_MUST_NOT_LEAK'},
      {...f.claim,claimSha256:'f'.repeat(64)},
      {...f.claim,caseworkReceiptId:crypto.randomUUID()},
      {...f.claim,bundleSha256:'a'.repeat(64)},
      {...f.claim,caseworkJournalSha256:'b'.repeat(64)},
      {...f.claim,terminalEventId:crypto.randomUUID()},
      {...f.claim,generationId:crypto.randomBytes(16).toString('hex')},
      {...f.claim,launchLedgerSha256:'c'.repeat(64)},
    ];
    const altered=[
      ['caseworkReceiptId',crypto.randomUUID()],
      ['bundleSha256','a'.repeat(64)],
      ['caseworkJournalSha256','b'.repeat(64)],
      ['terminalEventId',crypto.randomUUID()],
      ['generationId',crypto.randomBytes(16).toString('hex')],
      ['launchLedgerSha256','c'.repeat(64)],
    ];
    for(const [k,v] of altered) bad.push(claimed({...f.claim,[k]:v}));
    const getter={...f.claim};
    Object.defineProperty(getter,'generationId',{enumerable:true,
      get(){throw new Error('SECRET_MUST_NOT_LEAK');}});
    bad.push(getter);
    const proto=Object.create({foreign:'field'});
    Object.assign(proto,f.claim);
    bad.push(proto);
    for(const sample of bad) {
      const out=result(sample);
      hold(out,false);
      assert.ok(!JSON.stringify(out).includes('SECRET_MUST_NOT_LEAK'));
    }
  });
});

test('G41 refuses non-quarantined receipt, journal replacement and lock without repairing',async()=>{
  await fixture(async f=>{
    const fpath=f.casePath+'.lock';
    const stale=f.session.operator.assessCaseworkGenerationPin;
    const extra=f.casework.intakeMany([f.raw]).entries[0];
    assert.equal(extra.decision,'DUPLICATE');
    hold(stale(f.claim),false); // Claim pins the old Casework digest.
    const updated=claimed({
      ...f.claim,caseworkReceiptId:extra.id,
      caseworkJournalSha256:f.inspector().inspect().journalSha256,
    });
    hold(stale(updated),false); // A duplicate never becomes an origin.
    const sourceOriginal=fs.readFileSync(f.casePath);
    fs.writeFileSync(fpath,'LOCK_UNKNOWN',{mode:0o600});
    try {hold(stale(updated),false);}
    finally {fs.unlinkSync(fpath);}
    assert.deepEqual(fs.readFileSync(f.casePath),sourceOriginal);
    const replaced=path.join(f.cases,'replacement');
    fs.renameSync(f.casePath,replaced);
    fs.symlinkSync(replaced,f.casePath);
    hold(stale(updated),false);
  });
});

test('G41 stale Generation ledger and terminal evidence never match',async()=>{
  await fixture(async f=>{
    hold(f.session.operator.assessCaseworkGenerationPin(f.claim),true);
    f.journal.recordLaunch({
      generationId:crypto.randomBytes(16).toString('hex'),
      activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    });
    hold(f.session.operator.assessCaseworkGenerationPin(f.claim),false);
    // No hidden mutation of the Casework journal from failed correlation.
    assert.equal(f.inspector().inspect().journalSha256,
      f.claim.caseworkJournalSha256);
  });
});

test('G42 extended V2 manifest pins exact terminal event content without changing legacy G41',async()=>{
  await fixture(async f=>{
    const before=[fs.readFileSync(f.terminalPath),
      fs.readFileSync(f.casePath),fs.readFileSync(f.ledgerPath)];
    const digest=eventContentDigest(f.terminal);
    const claim=contentClaim(f.claim,digest);
    const output=f.session.operator.assessCaseworkGenerationPin(claim);
    hold(output,true);
    assert.equal(output.claimSha256,claim.claimSha256);
    assert.equal(output.terminalEventSha256,digest);
    assert.equal(output.eventContentBinding,
      'LOCAL_UNAUTHENTICATED_CONTENT_MATCH_ONLY');
    assert.equal(output.crossJournalBinding,
      'LOCAL_UNAUTHENTICATED_PIN_MATCH_ONLY');
    // Existing G41 manifests remain wire-compatible and never acquire
    // a content-binding label they did not request/verify.
    const legacy=f.session.operator.assessCaseworkGenerationPin(f.claim);
    hold(legacy,true);
    assert.equal(Object.hasOwn(legacy,'terminalEventSha256'),false);
    assert.equal(Object.hasOwn(legacy,'eventContentBinding'),false);
    assert.deepEqual([fs.readFileSync(f.terminalPath),
      fs.readFileSync(f.casePath),fs.readFileSync(f.ledgerPath)],before);
  });
});

test('G42 rejects recomputed claim hashes pinning wrong fault timestamp or error code',async()=>{
  await fixture(async f=>{
    const expected=eventContentDigest(f.terminal);
    const wrong=[
      '0'.repeat(64),
      eventContentDigest({...f.terminal,
        timestamp:'2020-01-01T00:00:00.000Z'}),
      eventContentDigest({...f.terminal,
        errorCode:'GUARDIAN_UNRELATED_FAILURE'}),
    ];
    for(const digest of wrong) {
      assert.notEqual(digest,expected);
      const claim=contentClaim(f.claim,digest);
      // The claim checksum is valid; only its event-content pin is wrong.
      assert.equal(claim.claimSha256,
        hash(JSON.stringify(Object.fromEntries(Object.entries(claim)
          .filter(([key])=>key!=='claimSha256')))));
      hold(f.session.operator.assessCaseworkGenerationPin(claim),false);
    }
    const valid=contentClaim(f.claim,expected);
    for (const invalid of [
      {...valid,terminalEventSha256:'not-sha256'},
      {...valid,terminalEventSha256:null},
      {...valid,secret:'NEVER_ECHO_THIS'},
      {...valid,claimSha256:'f'.repeat(64)},
    ]) {
      const out=f.session.operator.assessCaseworkGenerationPin(invalid);
      hold(out,false);
      assert.equal(JSON.stringify(out).includes('NEVER_ECHO_THIS'),false);
    }
    const accessor={...valid};
    Object.defineProperty(accessor,'terminalEventSha256',{
      enumerable:true,get(){throw Error('NEVER_ECHO_THIS');},
    });
    const out=f.session.operator.assessCaseworkGenerationPin(accessor);
    hold(out,false);
    assert.equal(JSON.stringify(out).includes('NEVER_ECHO_THIS'),false);
  });
});
