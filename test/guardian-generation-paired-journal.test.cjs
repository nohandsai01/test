'use strict';
// G31 real owner-only files + controlled read interleavings. This test
// never accesses hosted D1, GitHub App or process-control capabilities.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const {createGuardianLocalReceiptJournal,generationLedgerName}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const {createGuardianLocalDiagnostics}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const {createGuardianLocalEvidenceVerifier}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-evidence-verifier.cjs');

const NAME='guardian-generation-pair.jsonl';
function generation(){return crypto.randomBytes(16).toString('hex');}
function stopped(generationId,state='FAILED'){
  return {state,errorCode:state==='FAILED'?'GUARDIAN_CHILD_EXIT_UNVERIFIED':null,
    hostStopped:state==='STOPPED',generationId,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    automaticRestartAllowed:false};
}
function launched(id){return {generationId:id,activationAllowed:false,
  releaseAuthority:'NOT_ISSUED'};}
function controller(){return {status(){return {
  state:'STOPPED',pid:null,errorCode:null,generationId:null,
  activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false,
};}};}
async function temp(fn){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'nh-g31-pair-'));
  try{
    const writer=createGuardianLocalReceiptJournal({directory:dir,fileName:NAME});
    const journal=path.join(fs.realpathSync(dir),NAME);
    const ledger=path.join(fs.realpathSync(dir),generationLedgerName(NAME));
    const diag=createGuardianLocalDiagnostics({
      directory:dir,fileName:NAME,controller:controller(),
    });
    const verify=createGuardianLocalEvidenceVerifier({directory:dir,fileName:NAME});
    return await fn({dir,writer,diag,verify,journal,ledger});
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
function seed(f){
  const id=generation();
  f.writer.recordLaunch(launched(id));
  f.writer.append(stopped(id));
  return id;
}
function withInjectedOpen(target,count,callback,operation){
  const original=fs.openSync;
  let seen=0;
  fs.openSync=function(filename,...args){
    if(typeof filename==='string' &&
       path.resolve(filename)===path.resolve(target) && ++seen === count){
      callback();
    }
    return original.call(this,filename,...args);
  };
  try{
    return operation();
  }finally{
    fs.openSync=original;
  }
}
function hold(value){
  assert.equal(value.status,'SOURCE_ONLY_HOLD');
  assert.equal(value.releaseAuthority,'NOT_ISSUED');
  assert.equal(value.activationAllowed,false);
  assert.equal(value.automaticRestartAllowed,false);
}
test('G31 stable owner journal+ledger retains P1 and independently verified V2 incident',async()=>{
  await temp(async f=>{
    const id=seed(f);
    const baseline=f.diag.inspect();
    hold(baseline);
    assert.equal(baseline.reason,'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED');
    const triage=f.diag.faultTriage();
    assert.equal(triage.priority,'P1');
    assert.equal(triage.failureCount,1);
    const packet=f.diag.incidentEvidence();
    assert.equal(packet.schemaVersion,2);
    assert.equal(packet.generationId,id);
    assert.equal(f.verify.verify(packet).comparison,'MATCH_LOCAL_SNAPSHOT_ONLY');
  });
});
test('G31 terminal append while ledger first read is rejected (journal A/B/A mismatch)',async()=>{
  await temp(async f=>{
    seed(f);
    const inspected=withInjectedOpen(f.ledger,1,()=>{
      f.writer.append({state:'STOPPED',errorCode:null,
        hostStopped:true,activationAllowed:false,releaseAuthority:'NOT_ISSUED',
        automaticRestartAllowed:false});
    },()=>f.diag.inspect());
    hold(inspected);
    assert.equal(inspected.reason,'GUARDIAN_DIAGNOSTICS_PAIR_CHANGED_DURING_READ');
    assert.equal(inspected.journalSha256,null);
    assert.equal(f.diag.faultTriage().priority,'P1');
  });
});
test('G31 new generation launch while second journal read is rejected (ledger B/B mismatch)',async()=>{
  await temp(async f=>{
    seed(f);
    const out=withInjectedOpen(f.journal,2,()=> {
      f.writer.recordLaunch(launched(generation()));
    },()=>f.diag.faultTriage());
    hold(out);
    assert.equal(out.priority,'P0');
    assert.equal(out.sourceReason,
      'GUARDIAN_DIAGNOSTICS_PAIR_CHANGED_DURING_READ');
    assert.equal(out.journalSha256,null);
  });
});
test('G31 journal MISSING->PRESENT while reading paired ledger fails closed',async()=>{
  await temp(async f=>{
    const id=generation();f.writer.recordLaunch(launched(id));
    const out=withInjectedOpen(f.journal,2,()=>f.writer.append(stopped(id)),
      ()=>f.diag.inspect());
    hold(out);
    assert.equal(out.reason,'GUARDIAN_DIAGNOSTICS_PAIR_CHANGED_DURING_READ');
    assert.equal(out.journalEntries,0);
  });
});
test('G31 ledger PRESENT->MISSING during recheck is P0, not clean recovery',async()=>{
  await temp(async f=>{
    seed(f);
    const triage=withInjectedOpen(f.ledger,2,()=>{
      fs.unlinkSync(f.ledger);
    },()=>f.diag.faultTriage());
    hold(triage);
    assert.equal(triage.priority,'P0');
    assert.equal(triage.sourceReason,
      'GUARDIAN_DIAGNOSTICS_PAIR_CHANGED_DURING_READ');
  });
});
test('G31 same-size journal rewrite between paired reads cannot reuse stale fault evidence',async()=>{
  await temp(async f=>{
    seed(f);
    const packet=f.diag.incidentEvidence();
    const old=fs.readFileSync(f.journal,'utf8');
    const parsed=JSON.parse(old.trim());
    const replacement={...parsed,eventId:crypto.randomUUID()};
    const changed=JSON.stringify(replacement)+'\n';
    assert.equal(Buffer.byteLength(old),Buffer.byteLength(changed));
    const result=withInjectedOpen(f.ledger,1,()=>{
      fs.writeFileSync(f.journal,changed,{mode:0o600});
    },()=>f.diag.incidentEvidence());
    hold(result);
    assert.equal(result.availability,'UNAVAILABLE');
    assert.equal(result.reason,'GUARDIAN_EVIDENCE_SOURCE_UNVERIFIED');
    assert.equal(f.verify.verify(packet).comparison,'NOT_VERIFIED');
  });
});
test('G31 independent verifier refuses journal changed while first ledger read is in flight',async()=>{
  await temp(async f=>{
    seed(f);
    const packet=f.diag.incidentEvidence();
    assert.equal(f.verify.verify(packet).comparison,'MATCH_LOCAL_SNAPSHOT_ONLY');
    const result=withInjectedOpen(f.ledger,1,()=>{
      f.writer.append({state:'STOPPED',errorCode:null,
        hostStopped:true,activationAllowed:false,releaseAuthority:'NOT_ISSUED',
        automaticRestartAllowed:false});
    },()=>f.verify.verify(packet));
    hold(result);
    assert.equal(result.comparison,'NOT_VERIFIED');
    assert.equal(result.reason,'GUARDIAN_EVIDENCE_PAIR_CHANGED_DURING_READ');
    assert.equal(result.journalSha256,null);
  });
});
test('G31 verifier refuses ledger append during second journal read',async()=>{
  await temp(async f=>{
    seed(f);
    const packet=f.diag.incidentEvidence();
    const result=withInjectedOpen(f.journal,2,()=>{
      f.writer.recordLaunch(launched(generation()));
    },()=>f.verify.verify(packet));
    hold(result);
    assert.equal(result.comparison,'NOT_VERIFIED');
    assert.equal(result.reason,'GUARDIAN_EVIDENCE_PAIR_CHANGED_DURING_READ');
  });
});
test('G31 dual absent data remains untrusted CREATED baseline, never a verified clean stop',async()=>{
  await temp(async f=>{
    const observed=f.diag.inspect();
    hold(observed);
    assert.equal(observed.reason,'GUARDIAN_DIAGNOSTICS_JOURNAL_MISSING');
    assert.equal(observed.manualInterventionRequired,true);
    assert.equal(observed.journalSha256,null);
  });
});


test('G31 journal replaced with equal bytes during ledger read is rejected by inode',async()=>{
  await temp(async f=>{
    seed(f);
    const before=fs.readFileSync(f.journal);
    const first=fs.statSync(f.journal).ino;
    const out=withInjectedOpen(f.ledger,1,()=>{
      fs.renameSync(f.journal,f.journal+'.previous');
      fs.writeFileSync(f.journal,before,{mode:0o600});
    },()=>f.diag.inspect());
    assert.notEqual(fs.statSync(f.journal).ino,first);
    assert.deepEqual(fs.readFileSync(f.journal),before);
    hold(out);
    assert.equal(out.reason,'GUARDIAN_DIAGNOSTICS_PAIR_CHANGED_DURING_READ');
    assert.equal(out.journalSha256,null);
  });
});

test('G31 ledger replaced with byte-identical file cannot verify incident snapshot',async()=>{
  await temp(async f=>{
    seed(f);
    const packet=f.diag.incidentEvidence();
    assert.equal(f.verify.verify(packet).comparison,'MATCH_LOCAL_SNAPSHOT_ONLY');
    const bytes=fs.readFileSync(f.ledger),inode=fs.statSync(f.ledger).ino;
    const out=withInjectedOpen(f.journal,2,()=>{
      fs.renameSync(f.ledger,f.ledger+'.previous');
      fs.writeFileSync(f.ledger,bytes,{mode:0o600});
    },()=>f.verify.verify(packet));
    assert.notEqual(fs.statSync(f.ledger).ino,inode);
    assert.deepEqual(fs.readFileSync(f.ledger),bytes);
    hold(out);
    assert.equal(out.comparison,'NOT_VERIFIED');
    assert.equal(out.reason,'GUARDIAN_EVIDENCE_PAIR_CHANGED_DURING_READ');
  });
});
