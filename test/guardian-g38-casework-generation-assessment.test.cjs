'use strict';
// G38 source-only local two-domain observation; never authorizes release.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {createGuardianLocalOperatorSession}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const {createGuardianOfflineCasework}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-casework.cjs');
const {createGuardianCaseworkDiagnostics}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-casework-diagnostics.cjs');
const {createGuardianCaseworkGenerationAssessment}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-casework-generation-assessment.cjs');

const worker=path.join(__dirname,'guardian-protected-worker-child.cjs');
const name='guardian-g38-casework.jsonl';
async function fixture(run) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-g38-'));
  const source=path.join(root,'source'),caseDir=path.join(root,'casework');
  fs.mkdirSync(source,{mode:0o700});
  fs.mkdirSync(caseDir,{mode:0o700});
  const options={cwd:path.dirname(worker),entrypoint:worker,
    directory:source,fileName:'guardian-g38-source.jsonl',
    startupTimeoutMs:4000,shutdownTimeoutMs:700,
    caseworkDirectory:caseDir,caseworkFileName:name};
  const session=createGuardianLocalOperatorSession(options);
  const writer=()=>createGuardianOfflineCasework({directory:caseDir,fileName:name});
  const reader=()=>createGuardianCaseworkDiagnostics({directory:caseDir,fileName:name});
  try {return await run({root,source,caseDir,session,writer,reader,options});}
  finally {fs.rmSync(root,{recursive:true,force:true});}
}
function checkHold(x) {
  assert.equal(x.kind,'GUARDIAN_CASEWORK_GENERATION_ASSESSMENT_V1');
  assert.equal(x.status,'SOURCE_ONLY_HOLD');
  assert.equal(x.authority,'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(x.liveness,'NOT_PROVEN');
  assert.equal(x.custodyVerified,false);
  assert.equal(x.automaticRestartAllowed,false);
  assert.equal(x.activationAllowed,false);
  assert.equal(x.releaseAuthority,'NOT_ISSUED');
  assert.equal(x.manualInterventionRequired,true);
  assert.equal(x.crossJournalBinding,'NOT_PROVEN');
  assert.equal(x.generationLedgerBinding,'NOT_PROVEN');
  assert.ok(Object.isFrozen(x));
  for (const key of ['path','pid','generationId','entrypoint',
    'rawJournal','bundle','token','secret','signer','unlock','start',
    'stop','reset','publishCheck','writeD1','releaseHold']) {
    assert.equal(Object.hasOwn(x,key),false);
  }
}
function addRejectedCasework(f) {
  const entries=f.writer().intakeMany(['{"token":"MUST_NOT_ECHO"}']).entries;
  assert.equal(entries.length,1);
  assert.equal(entries[0].decision,'REJECTED');
}
async function stoppedCase(f) {
  assert.equal((await f.session.owner.start()).state,'RUNNING');
  assert.equal((await f.session.owner.stop()).state,'STOPPED');
  addRejectedCasework(f);
}
function makeAssessor(f,override={}) {
  const op=f.session.operator;
  return createGuardianCaseworkGenerationAssessment({
    caseworkDiagnostics:override.caseworkDiagnostics??f.reader(),
    operator:override.operator??{
      assessRuntime:()=>op.assessRuntime(),
      captureOfflineIncidentBrief:()=>op.captureOfflineIncidentBrief(),
      auditCompleteEventLedger:()=>op.auditCompleteEventLedger(),
    },
  });
}

test('G38 opt-in scope rejects partial paths; original Operator surface remains unchanged',async()=>{
  await fixture(async f=>{
    const baseline=createGuardianLocalOperatorSession({
      cwd:f.options.cwd,entrypoint:f.options.entrypoint,
      directory:f.source,fileName:f.options.fileName,
    });
    assert.equal(Object.hasOwn(baseline.operator,
      'assessCaseworkGenerationEvidence'),false);
    assert.equal(typeof f.session.operator.assessCaseworkGenerationEvidence,
      'function');
    assert.throws(()=>createGuardianLocalOperatorSession({
      ...f.options,caseworkFileName:undefined,
    }),/CASEWORK/);
    assert.throws(()=>createGuardianLocalOperatorSession({
      ...f.options,caseworkDirectory:undefined,
    }),/CASEWORK/);
    assert.deepEqual(fs.readdirSync(f.source),[]);
    assert.deepEqual(fs.readdirSync(f.caseDir),[]);
    const result=f.session.operator.assessCaseworkGenerationEvidence();
    checkHold(result);
    assert.equal(result.classification,'NOT_VERIFIED');
    assert.equal(result.reason,'GUARDIAN_CASEWORK_SOURCE_UNVERIFIED');
    assert.equal(result.caseworkJournalSha256,null);
    assert.deepEqual(fs.readdirSync(f.source),[]);
    assert.deepEqual(fs.readdirSync(f.caseDir),[]);
  });
});

test('G38 authentic V2 lifecycle and offline casework coexist but never assert a binding',async()=>{
  await fixture(async f=>{
    await stoppedCase(f);
    const before=fs.readFileSync(path.join(f.caseDir,name));
    const caseSha=f.reader().inspect().journalSha256;
    const result=f.session.operator.assessCaseworkGenerationEvidence();
    checkHold(result);
    assert.equal(result.classification,'LOCAL_COINCIDENT_OBSERVATIONS_ONLY');
    assert.equal(result.reason,'GUARDIAN_CASEWORK_GENERATION_LOCAL_SNAPSHOTS');
    assert.equal(result.priority,'P3');
    assert.equal(result.unterminatedGenerations,0);
    assert.equal(result.caseworkJournalSha256,caseSha);
    assert.match(result.terminalJournalSha256,/^[0-9a-f]{64}$/);
    assert.match(result.orderedEventsSha256,/^[0-9a-f]{64}$/);
    assert.deepEqual(result.caseworkCounts,{
      receipts:1,quarantined:0,duplicates:0,rejected:1,handoffs:0,returns:0,
    });
    assert.ok(Object.isFrozen(result.caseworkCounts));
    assert.equal(result.terminalFailures,0);
    assert.deepEqual(fs.readFileSync(path.join(f.caseDir,name)),before);
    assert.ok(!JSON.stringify(result).includes('MUST_NOT_ECHO'));
  });
});

test('G38 present casework lock, corrupt records and unsafe journal fail closed',async()=>{
  await fixture(async f=>{
    await stoppedCase(f);
    const file=path.join(f.caseDir,name),original=fs.readFileSync(file);
    fs.writeFileSync(file+'.lock','possibly-active',{mode:0o600});
    let result=f.session.operator.assessCaseworkGenerationEvidence();
    checkHold(result);
    assert.equal(result.priority,'P0');
    assert.equal(result.caseworkJournalSha256,null);
    fs.unlinkSync(file+'.lock');
    fs.appendFileSync(file,'{"duplicate":"unsafe"}\n');
    result=f.session.operator.assessCaseworkGenerationEvidence();
    checkHold(result);
    assert.equal(result.classification,'NOT_VERIFIED');
    assert.equal(result.terminalJournalSha256,null);
    fs.writeFileSync(file,original);
    fs.chmodSync(file,0o644);
    result=f.session.operator.assessCaseworkGenerationEvidence();
    checkHold(result);
    assert.equal(result.priority,'P0');
  });
});

test('G38 double casework read rejects changed journal digest between domains',async()=>{
  await fixture(async f=>{
    await stoppedCase(f);
    const genuine=f.reader(),original=genuine.inspect();
    let calls=0;
    const d={inspect(){
      calls++;
      return calls===2 ? Object.freeze({
        ...original,journalSha256:'a'.repeat(64),
      }):original;
    }};
    const out=makeAssessor(f,{caseworkDiagnostics:d}).assess();
    checkHold(out);
    assert.equal(calls,2);
    assert.equal(out.classification,'NOT_VERIFIED');
    assert.equal(out.reason,'GUARDIAN_CORRELATION_SNAPSHOTS_CHANGED');
    assert.equal(out.caseworkCounts,null);
  });
});

test('G38 runtime generation drift and brief mismatch never become coincident observations',async()=>{
  await fixture(async f=>{
    await stoppedCase(f);
    const op=f.session.operator;
    const real=op.assessRuntime();
    let reads=0;
    const result=makeAssessor(f,{operator:{
      assessRuntime:()=>{
        reads++;
        return reads===1?real:Object.freeze({
          ...real,unterminatedGenerations:1,
        });
      },
      captureOfflineIncidentBrief:()=>op.captureOfflineIncidentBrief(),
      auditCompleteEventLedger:()=>op.auditCompleteEventLedger(),
    }}).assess();
    checkHold(result);
    assert.equal(reads,2);
    assert.equal(result.classification,'NOT_VERIFIED');
    const mismatch=makeAssessor(f,{operator:{
      assessRuntime:()=>op.assessRuntime(),
      captureOfflineIncidentBrief:()=>Object.freeze({
        ...op.captureOfflineIncidentBrief(),journalSha256:'a'.repeat(64),
      }),
      auditCompleteEventLedger:()=>op.auditCompleteEventLedger(),
    }}).assess();
    checkHold(mismatch);
    assert.equal(mismatch.classification,'NOT_VERIFIED');
    assert.equal(mismatch.terminalJournalSha256,null);
  });
});

test('G38 casework diagnostics re-read catches mid-inspection rewrite before a clean lock result',async()=>{
  await fixture(async f=>{
    addRejectedCasework(f);
    const file=path.join(fs.realpathSync(f.caseDir),name);
    const realOpen=fs.openSync;
    let opens=0;
    try {
      fs.openSync=function(target,...rest){
        if (target===file) {
          opens++;
          if (opens===2) fs.appendFileSync(file,'{"unexpected":"record"}\n');
        }
        return realOpen.call(fs,target,...rest);
      };
      const result=f.reader().inspect();
      assert.equal(opens,2);
      assert.equal(result.result,'NOT_VERIFIED');
      assert.equal(result.reason,'GUARDIAN_DIAG_CHANGED_DURING_READ');
    } finally {
      fs.openSync=realOpen;
    }
  });
});
