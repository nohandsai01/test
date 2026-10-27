'use strict';
// G27–G30 follow-on: in-process concurrent generation reconciliation +
// independently hashed generation-bound incident evidence. Isolated SQLite,
// local synthetic child fixture, no live App/D1/Check.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const { createGuardianLocalOperatorSession }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianLocalReceiptJournal, generationLedgerName,
  observeLocalActiveGenerations }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalDiagnostics }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const { createGuardianLocalEvidenceVerifier }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-evidence-verifier.cjs');

const worker=path.join(__dirname,'guardian-protected-worker-child.cjs');
const FILE='guardian-linked-evidence.jsonl';
const GUID=/^[0-9a-f]{32}$/;
const SHA=/^[0-9a-f]{64}$/;
function temporary(fn){
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'nh-g27-linked-'));
  return Promise.resolve().then(()=>fn(directory))
    .finally(()=>fs.rmSync(directory,{recursive:true,force:true}));
}
function factory(dir){
  return createGuardianLocalOperatorSession({
    cwd:path.dirname(worker),entrypoint:worker,directory:dir,
    fileName:FILE,startupTimeoutMs:4000,shutdownTimeoutMs:900,
  });
}
function writer(dir){
  return createGuardianLocalReceiptJournal({directory:dir,fileName:FILE});
}
function synthetic(status='STOPPED',generationId=null){
  return {status(){return Object.freeze({
    state:status,pid:null,errorCode:null,generationId,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    automaticRestartAllowed:false,
  });}};
}
function diagnostics(dir){
  return createGuardianLocalDiagnostics({
    controller:synthetic(),directory:dir,fileName:FILE,
  });
}
function verifier(dir){
  return createGuardianLocalEvidenceVerifier({directory:dir,fileName:FILE});
}
function stop(generationId,state='FAILED'){
  return {state,errorCode:state==='FAILED' ?
    'GUARDIAN_CHILD_EXIT_UNVERIFIED' : null,
    hostStopped:state==='STOPPED',generationId,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    automaticRestartAllowed:false};
}
function ledgerDigest(dir){
  const bytes=fs.readFileSync(path.join(dir,generationLedgerName(FILE)));
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function rehash(packet){
  const entries={...packet};
  delete entries.evidenceSha256;
  packet.evidenceSha256=crypto.createHash('sha256')
    .update(JSON.stringify(entries),'utf8').digest('hex');
}
function assertHold(data){
  assert.equal(data.status,'SOURCE_ONLY_HOLD');
  assert.equal(data.releaseAuthority,'NOT_ISSUED');
  assert.equal(data.activationAllowed,false);
  assert.equal(data.automaticRestartAllowed,false);
}

test('two truly running protected child sessions in one Node process do not yield false P1',async()=>{
  await temporary(async(dir)=>{
    const first=factory(dir),second=factory(dir);
    try{
      const a=await first.owner.start();
      assert.equal(a.state,'RUNNING');
      const b=await second.owner.start();
      assert.equal(b.state,'RUNNING');
      assert.notEqual(a.generationId,b.generationId);
      const local=observeLocalActiveGenerations(fs.realpathSync(dir),FILE);
      assert.equal(local.length,2);
      for(const s of [first,second]){
        const triage=s.operator.faultTriage();
        assertHold(triage);
        assert.equal(triage.priority,'P2');
        assert.equal(triage.classification,'PROCESS_STATE_UNPROVEN');
        assert.equal(triage.unterminatedGenerations,0);
        assert.equal(triage.concurrentGenerations,1);
        assert.equal(triage.sourceReason,
          'GUARDIAN_DIAGNOSTICS_CONCURRENT_GENERATION_OBSERVED');
      }
      assert.equal((await first.owner.stop()).state,'STOPPED');
      const after=first.operator.faultTriage();
      assert.equal(after.priority,'P2');
      assert.equal(after.unterminatedGenerations,0);
      assert.equal(after.concurrentGenerations,1);
      assert.equal((await second.owner.stop()).state,'STOPPED');
      assert.equal(observeLocalActiveGenerations(fs.realpathSync(dir),FILE).length,0);
      assert.equal(first.operator.faultTriage().priority,'P3');
      assert.equal(second.operator.faultTriage().priority,'P3');
    } finally {
      await Promise.allSettled([first.owner.stop(),second.owner.stop()]);
    }
  });
});

test('crashed generation from older process is still P1 even with a newer active local session',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir),dead=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:dead,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    const now=factory(dir);
    try{
      const ready=await now.owner.start();
      assert.equal(ready.state,'RUNNING');
      const r=now.operator.faultTriage();
      assertHold(r);
      assert.equal(r.priority,'P1');
      assert.equal(r.classification,'UNTERMINATED_GENERATION');
      assert.equal(r.unterminatedGenerations,1);
      assert.equal(r.concurrentGenerations,0);
      assert.equal((await now.owner.stop()).state,'STOPPED');
      const history=now.operator.faultTriage();
      assert.equal(history.priority,'P1');
      assert.equal(history.unterminatedGenerations,1);
    } finally {await now.owner.stop();}
  });
});

test('v2 fault packet binds event generation and entire owner-only launch ledger SHA',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir);
    const id=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:id,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    j.append(stop(id));
    const packet=diagnostics(dir).incidentEvidence();
    assertHold(packet);
    assert.equal(packet.schemaVersion,2);
    assert.equal(packet.kind,'GUARDIAN_LOCAL_FAULT_EVIDENCE_V2');
    assert.equal(packet.availability,'LOCAL_SNAPSHOT');
    assert.equal(packet.generationId,id);
    assert.equal(packet.launchLedgerSha256,ledgerDigest(dir));
    assert.match(packet.evidenceSha256,SHA);
    assert.equal(packet.selectedFailure.generationId,id);
    assert.equal(packet.firstFailure.generationId,id);
    assert.equal(packet.latestFailure.generationId,id);
    assert.equal(Object.isFrozen(packet.selectedFailure),true);
    assert.equal(verifier(dir).verify(packet).comparison,
      'MATCH_LOCAL_SNAPSHOT_ONLY');
    assert.equal(verifier(dir).verify(packet).custodyVerified,false);
  });
});

test('cross-generation spoof fails even after recomputing the attacker-controlled checksum',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir),id=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:id,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    j.append(stop(id));
    const original=diagnostics(dir).incidentEvidence();
    const adversaries=[
      (x)=>{x.generationId=crypto.randomBytes(16).toString('hex');},
      (x)=>{x.selectedFailure.generationId=crypto.randomBytes(16).toString('hex');},
      (x)=>{x.firstFailure.generationId=null;},
      (x)=>{x.launchLedgerSha256='f'.repeat(64);},
      (x)=>{x.selectedFailure.token='SECRET_DO_NOT_COPY';},
    ];
    for(const attack of adversaries){
      const modified=structuredClone(original);
      attack(modified);
      rehash(modified);
      const r=verifier(dir).verify(modified);
      assertHold(r);
      assert.equal(r.comparison,'NOT_VERIFIED');
      assert.equal(r.journalSha256,null);
      assert.ok(!JSON.stringify(r).includes('SECRET_DO_NOT_COPY'));
    }
  });
});

test('ledger changed after packet creation invalidates the old incident while journal is unchanged',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir),id=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:id,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    j.append(stop(id));
    const packet=diagnostics(dir).incidentEvidence();
    j.recordLaunch({generationId:crypto.randomBytes(16).toString('hex'),
      activationAllowed:false,releaseAuthority:'NOT_ISSUED'});
    const result=verifier(dir).verify(packet);
    assertHold(result);
    assert.equal(result.comparison,'NOT_VERIFIED');
    assert.equal(result.reason,
      'GUARDIAN_EVIDENCE_GENERATION_LEDGER_UNVERIFIED');
  });
});

test('missing, replaced, duplicate or reordered generation ledger never verifies old v2 packet',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir),id=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:id,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    j.append(stop(id));
    const packet=diagnostics(dir).incidentEvidence();
    const file=path.join(dir,generationLedgerName(FILE));
    const bytes=fs.readFileSync(file);
    const row=JSON.parse(bytes.toString('utf8').trim());
    const cases=[
      null,
      Buffer.concat([bytes,bytes]),
      Buffer.from(bytes.toString('utf8').replace(
        '"schemaVersion":1,','"schemaVersion":1,"schemaVersion":1,')),
      Buffer.from(bytes.toString('utf8').replace(
        '"generationId":"'+id+'"',
        '"generationId":"'+crypto.randomBytes(16).toString('hex')+'"')),
    ];
    for(const broken of cases){
      if(broken===null) fs.unlinkSync(file);
      else fs.writeFileSync(file,broken,{mode:0o600});
      const outcome=verifier(dir).verify(packet);
      assert.equal(outcome.comparison,'NOT_VERIFIED');
      assertHold(outcome);
    }
  });
});

test('v1 fault packet remains verifiable; v2 cannot be downgraded to a fake legacy envelope',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir);
    j.append({state:'FAILED',errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',
      hostStopped:false,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED',automaticRestartAllowed:false});
    const legacy=diagnostics(dir).incidentEvidence();
    assert.equal(legacy.schemaVersion,1);
    assert.equal(legacy.kind,'GUARDIAN_LOCAL_FAULT_EVIDENCE_V1');
    assert.equal(verifier(dir).verify(legacy).comparison,
      'MATCH_LOCAL_SNAPSHOT_ONLY');
    const newer=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:newer,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    j.append(stop(newer));
    const v2=diagnostics(dir).incidentEvidence();
    assert.equal(v2.schemaVersion,2);
    const fake=structuredClone(v2);
    delete fake.generationId;
    delete fake.launchLedgerSha256;
    fake.schemaVersion=1;
    fake.kind='GUARDIAN_LOCAL_FAULT_EVIDENCE_V1';
    for(const key of ['selectedFailure','firstFailure','latestFailure']){
      delete fake[key].generationId;
    }
    if(fake.previousReceipt)delete fake.previousReceipt.generationId;
    if(fake.nextReceipt)delete fake.nextReceipt.generationId;
    rehash(fake);
    const mismatch=verifier(dir).verify(fake);
    assert.equal(mismatch.comparison,'NOT_VERIFIED');
  });
});


test('launch-only generation never becomes local LIVE before verified V2 READY',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir),id=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:id,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    assert.deepEqual(observeLocalActiveGenerations(fs.realpathSync(dir),FILE),[]);
    assert.equal(diagnostics(dir).faultTriage().priority,'P1');
    assert.equal(diagnostics(dir).faultTriage().classification,
      'UNTERMINATED_GENERATION');
    assert.throws(()=>j.recordReady({generationId:
      crypto.randomBytes(16).toString('hex'),
      activationAllowed:false,releaseAuthority:'NOT_ISSUED'}),
    {code:'GUARDIAN_JOURNAL_READY_INVALID'});
    assert.equal(observeLocalActiveGenerations(fs.realpathSync(dir),FILE).length,0);
  });
});

test('verified readiness callback rejecting synchronously fails before RUNNING and does not mask P1',async()=>{
  await temporary(async(dir)=>{
    const {createGuardianLocalProcessController}=require(
      '../merge-gate-install/guardian-candidate/guardian-local-process-controller.cjs');
    const j=writer(dir);
    const ctrl=createGuardianLocalProcessController({
      cwd:path.dirname(worker),entrypoint:worker,
      startupTimeoutMs:1500,shutdownTimeoutMs:700,
      onLaunch:j.recordLaunch, onTerminal:j.append,
      onReady(){throw new Error('synthetic supervisor veto');},
    });
    await assert.rejects(ctrl.start(),
      {code:'GUARDIAN_CHILD_READY_RECORD_FAILED'});
    assert.equal(ctrl.status().state,'FAILED');
    assert.equal(observeLocalActiveGenerations(fs.realpathSync(dir),FILE).length,0);
    assert.notEqual(diagnostics(dir).faultTriage().priority,'P3');
  });
});

test('async ready callback is fail closed and cannot establish an in-process witness',async()=>{
  await temporary(async(dir)=>{
    const {createGuardianLocalProcessController}=require(
      '../merge-gate-install/guardian-candidate/guardian-local-process-controller.cjs');
    const j=writer(dir);
    const ctrl=createGuardianLocalProcessController({
      cwd:path.dirname(worker),entrypoint:worker,
      startupTimeoutMs:1500,shutdownTimeoutMs:700,
      onLaunch:j.recordLaunch,onTerminal:j.append,
      onReady:async()=>({witnessed:true}),
    });
    await assert.rejects(ctrl.start(),
      {code:'GUARDIAN_CHILD_READY_RECORD_FAILED'});
    assert.equal(ctrl.status().state,'FAILED');
    assert.deepEqual(observeLocalActiveGenerations(fs.realpathSync(dir),FILE),[]);
  });
});

test('v2 generation packet with wrong field types or dynamic metadata is not accepted',async()=>{
  await temporary(async(dir)=>{
    const j=writer(dir),id=crypto.randomBytes(16).toString('hex');
    j.recordLaunch({generationId:id,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED'});
    j.append(stop(id));
    const valid=diagnostics(dir).incidentEvidence();
    for(const change of [
      packet=>{packet.generationId={toString(){
        throw new Error('DO_NOT_LEAK_PRIVATE_KEY');
      }};},
      packet=>{packet.launchLedgerSha256=null;},
      packet=>{packet.selectedFailure.generationId='not-a-generation';},
      packet=>{packet.extra='SECRET_D1';},
    ]){
      const bad=structuredClone(valid);
      change(bad);
      // For pathological type data, never call JSON.stringify ourselves.
      const outcome=verifier(dir).verify(bad);
      assertHold(outcome);
      assert.equal(outcome.comparison,'NOT_VERIFIED');
      assert.ok(!JSON.stringify(outcome).includes('PRIVATE_KEY'));
      assert.ok(!JSON.stringify(outcome).includes('SECRET_D1'));
    }
  });
});
