'use strict';
// G27F passive diagnostics: no automatic lock cleanup, no incident mutation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianCaseworkDiagnostics } =
  require('../merge-gate-install/guardian-candidate/guardian-local-casework-diagnostics.cjs');
const { createGuardianOfflineCasework } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-casework.cjs');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession } =
  require('../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianOfflineIncidentBrief } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { makeBundle } =
  require('../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const stopped = Object.freeze({state:'STOPPED',errorCode:null,
  hostStopped:true,activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false});
const failed = Object.freeze({state:'FAILED',
  errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',hostStopped:false,
  activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false});
async function temp(run) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-g27f-'));
  const source=path.join(root,'source');
  const intake=path.join(root,'inbox');
  fs.mkdirSync(source,{mode:0o700});fs.mkdirSync(intake,{mode:0o700});
  const journal=createGuardianLocalReceiptJournal({
    directory:source,fileName:'guardian-source.jsonl',
  });
  const operator=createGuardianLocalOperatorSession({
    cwd:path.dirname(worker),entrypoint:worker,
    directory:source,fileName:'guardian-source.jsonl',
  }).operator;
  const capture=()=>createGuardianOfflineIncidentBrief({
    operator,limit:10,
  }).capture();
  const input=()=>{
    journal.append(stopped); const a=capture();
    journal.append(failed); const b=capture();
    return JSON.stringify(makeBundle([a,b]));
  };
  const file=path.join(intake,'guardian-audit.jsonl');
  const lock=file+'.lock';
  const writer=()=>createGuardianOfflineCasework({
    directory:intake,fileName:'guardian-audit.jsonl',
  });
  const diag=(extras={})=>createGuardianCaseworkDiagnostics({
    directory:intake,fileName:'guardian-audit.jsonl',...extras,
  });
  try {return await run({root,source,intake,journal,capture,input,
    writer,diag,file,lock});}
  finally {fs.rmSync(root,{recursive:true,force:true});}
}
function hold(result) {
  assert.equal(result.schemaVersion,1);
  assert.equal(result.kind,'GUARDIAN_CASEWORK_DIAGNOSTICS_V1');
  assert.equal(result.status,'SOURCE_ONLY_HOLD');
  assert.equal(result.authority,'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(result.liveness,'NOT_PROVEN');
  assert.equal(result.custodyVerified,false);
  assert.equal(result.manualInterventionRequired,true);
  assert.equal(result.automaticRestartAllowed,false);
  assert.equal(result.activationAllowed,false);
  assert.equal(result.releaseAuthority,'NOT_ISSUED');
  assert.ok(Object.isFrozen(result));
  for (const key of ['path','pid','token','key','unlock','unlink',
    'restart','repair','checkWriter','rawRows']) {
    assert.equal(Object.hasOwn(result,key),false);
  }
}
function snapshot(dir) {
  return Object.fromEntries(fs.readdirSync(dir).map(name=>{
    const p=path.join(dir,name),st=fs.lstatSync(p);
    return [name,{data:st.isFile()?fs.readFileSync(p):null,
      mode:st.mode,nlink:st.nlink,ctime:st.ctimeMs,mtime:st.mtimeMs}];
  }));
}
function noChanges(before,after) {
  assert.deepEqual(Object.keys(after).sort(),Object.keys(before).sort());
  for(const key of Object.keys(before)){
    assert.deepEqual(after[key].data,before[key].data);
    assert.equal(after[key].mode,before[key].mode);
    assert.equal(after[key].nlink,before[key].nlink);
    assert.equal(after[key].mtime,before[key].mtime);
  }
}
test('import/construction inert; missing casework journal and no lock remain untouched',async()=>{
  await temp(async f=>{
    const before=snapshot(f.intake);
    const d=f.diag();
    assert.ok(Object.isFrozen(d));
    assert.deepEqual(Object.keys(d),['inspect','inspectQuarantinedReceipt']);
    noChanges(before,snapshot(f.intake));
    const observation=d.inspect();
    hold(observation);
    assert.equal(observation.result,'NOT_VERIFIED');
    assert.equal(observation.journalState,'JOURNAL_MISSING');
    assert.equal(observation.lockState,'LOCK_ABSENT_OBSERVED');
    assert.equal(observation.counts,null);
    noChanges(before,snapshot(f.intake));
  });
});
test('existing clean journal and absent lock report only local structural observation',async()=>{
  await temp(async f=>{
    const raw=f.input(),cw=f.writer();
    const entries=cw.intakeMany([raw,raw]).entries;
    cw.handoff({receiptId:entries[0].id,transition:'REQUESTED'});
    cw.handoff({receiptId:entries[0].id,transition:'ACKNOWLEDGED'});
    cw.handoff({receiptId:entries[0].id,transition:'RETURNED'});
    const before=snapshot(f.intake);
    const out=f.diag().inspect();
    hold(out);
    assert.equal(out.result,'LOCAL_STRUCTURE_OBSERVED_ONLY');
    assert.equal(out.reason,'GUARDIAN_DIAG_LOCAL_STRUCTURE_OBSERVED');
    assert.equal(out.journalState,'JOURNAL_STRUCTURALLY_CONSISTENT');
    assert.equal(out.lockState,'LOCK_ABSENT_OBSERVED');
    assert.match(out.journalSha256,/^[0-9a-f]{64}$/);
    assert.ok(Object.isFrozen(out.counts));
    assert.deepEqual(out.counts,{
      receipts:5,quarantined:1,duplicates:1,rejected:0,handoffs:3,returns:1,
    });
    noChanges(before,snapshot(f.intake));
  });
});
test('valid malformed submission contributes rejected count but no raw data',async()=>{
  await temp(async f=>{
    const cw=f.writer(),bad=cw.intakeMany(['{"token":"DO_NOT_ECHO"}']).entries;
    assert.equal(bad[0].decision,'REJECTED');
    const out=f.diag().inspect();
    hold(out);
    assert.equal(out.result,'LOCAL_STRUCTURE_OBSERVED_ONLY');
    assert.equal(out.counts.rejected,1);
    assert.ok(!JSON.stringify(out).includes('DO_NOT_ECHO'));
  });
});
test('present lock does not get timed out, unlinked, or called stale by diagnostics',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw]);
    fs.writeFileSync(f.lock,'maybe-live-writer',{mode:0o600});
    const old=new Date('2001-01-01T00:00:00.000Z');
    fs.utimesSync(f.lock,old,old);
    const before=snapshot(f.intake);
    const result=f.diag().inspect();
    hold(result);
    assert.equal(result.result,'NOT_VERIFIED');
    assert.equal(result.lockState,'LOCK_PRESENT_UNVERIFIED');
    assert.equal(result.reason,'GUARDIAN_DIAG_LOCK_REQUIRES_OWNER_REVIEW');
    assert.equal(result.journalState,'JOURNAL_STRUCTURALLY_CONSISTENT');
    assert.equal(result.counts.quarantined,1);
    noChanges(before,snapshot(f.intake));
    assert.equal(fs.readFileSync(f.lock,'utf8'),'maybe-live-writer');
  });
});
test('lock-only from uncertain prior writer is observed but never cleared',async()=>{
  await temp(async f=>{
    fs.writeFileSync(f.lock,'left-after-crash',{mode:0o600});
    const result=f.diag().inspect();
    hold(result);
    assert.equal(result.journalState,'JOURNAL_MISSING');
    assert.equal(result.lockState,'LOCK_PRESENT_UNVERIFIED');
    assert.equal(result.result,'NOT_VERIFIED');
    assert.equal(fs.readFileSync(f.lock,'utf8'),'left-after-crash');
    assert.equal(f.writer().intakeMany(['garbage']).decision,'NOT_VERIFIED');
  });
});
test('lock symlink, weak permissions or multiply-linked lock are unsafe and never removed',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw]);
    const diag=f.diag();
    fs.symlinkSync('/dev/null',f.lock);
    assert.equal(diag.inspect().lockState,'LOCK_UNSAFE');
    assert.ok(fs.lstatSync(f.lock).isSymbolicLink());
    fs.unlinkSync(f.lock);
    fs.writeFileSync(f.lock,'LOCK',{mode:0o600});
    fs.chmodSync(f.lock,0o644);
    assert.equal(diag.inspect().lockState,'LOCK_UNSAFE');
    fs.chmodSync(f.lock,0o600);
    const hard=path.join(f.intake,'guardian-link');
    fs.linkSync(f.lock,hard);
    assert.equal(diag.inspect().lockState,'LOCK_UNSAFE');
    assert.equal(fs.readFileSync(f.lock,'utf8'),'LOCK');
  });
});
test('truncated, duplicate JSON member and forged receipt kind fail-closed',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw]);
    const original=fs.readFileSync(f.file);
    for (const next of [
      original.subarray(0,original.length-1),
      Buffer.from(original.toString('utf8').replace('"schemaVersion":1,',
        '"schemaVersion":1,"schemaVersion":1,')),
      Buffer.from(original.toString('utf8').replace(
        '"kind":"GUARDIAN_CASEWORK_RECEIPT_V1"',
        '"kind":"GUARDIAN_FAKE_KIND_V1"')),
      Buffer.concat([original,Buffer.from('not-json\n')]),
    ]) {
      assert.equal(next.equals(original),false);
      fs.writeFileSync(f.file,next);
      const out=f.diag().inspect(); hold(out);
      assert.equal(out.result,'NOT_VERIFIED');
      assert.equal(out.journalState,'JOURNAL_INVALID');
      assert.equal(out.journalSha256,null);
      assert.equal(out.counts,null);
    }
  });
});
test('duplicate receipt identity and invalid duplicate reference cannot appear consistent',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw,raw]);
    const original=fs.readFileSync(f.file,'utf8');
    const rows=original.trim().split('\n').map(JSON.parse);
    const duplicate=structuredClone(rows);
    duplicate[1].id=duplicate[0].id;
    const forged=structuredClone(rows);
    forged[1].originalId='00000000-0000-4000-8000-000000000009';
    for(const input of [duplicate,forged]) {
      fs.writeFileSync(f.file,input.map(JSON.stringify).join('\n')+'\n');
      const result=f.diag().inspect(); hold(result);
      assert.equal(result.journalState,'JOURNAL_INVALID');
      assert.equal(result.result,'NOT_VERIFIED');
    }
  });
});
test('illegal handoff ordering or an unknown subject never passes journal validation',async()=>{
  await temp(async f=>{
    const raw=f.input(),cw=f.writer();
    const a=cw.intakeMany([raw]).entries[0];
    cw.handoff({receiptId:a.id,transition:'REQUESTED'});
    cw.handoff({receiptId:a.id,transition:'ACKNOWLEDGED'});
    const baseline=fs.readFileSync(f.file,'utf8').trim().split('\n').map(JSON.parse);
    const invalid1=structuredClone(baseline);
    invalid1[1].transition='ACKNOWLEDGED';
    invalid1[1].reason='GUARDIAN_CASEWORK_HANDOFF_ACKNOWLEDGED';
    const invalid2=structuredClone(baseline);
    invalid2[2].subjectId='00000000-0000-4000-8000-000000000004';
    for(const altered of [invalid1,invalid2]){
      fs.writeFileSync(f.file,altered.map(JSON.stringify).join('\n')+'\n');
      const result=f.diag().inspect();hold(result);
      assert.equal(result.journalState,'JOURNAL_INVALID');
      assert.equal(result.counts,null);
    }
  });
});
test('journal symlink, unsafe mode and hardlink are never treated as complete',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw]);
    const d=f.diag();
    fs.chmodSync(f.file,0o644);
    assert.equal(d.inspect().journalState,'JOURNAL_UNVERIFIED');
    fs.chmodSync(f.file,0o600);
    const hard=path.join(f.intake,'guardian-hardlink');
    fs.linkSync(f.file,hard);
    assert.equal(d.inspect().journalState,'JOURNAL_UNVERIFIED');
    fs.unlinkSync(hard);
    fs.unlinkSync(f.file);
    fs.symlinkSync('/dev/null',f.file);
    assert.notEqual(d.inspect().result,'LOCAL_STRUCTURE_OBSERVED_ONLY');
    assert.ok(fs.lstatSync(f.file).isSymbolicLink());
  });
});
test('oversized, empty, non-UTF8 and excessively many rows do not yield clean status',async()=>{
  await temp(async f=>{
    const d=f.diag({maxJournalBytes:1024});
    fs.writeFileSync(f.file,Buffer.alloc(2048,65),{mode:0o600});
    assert.equal(d.inspect().journalState,'JOURNAL_UNVERIFIED');
    fs.writeFileSync(f.file,'');
    assert.equal(d.inspect().journalState,'JOURNAL_UNVERIFIED');
    fs.writeFileSync(f.file,Buffer.from([0xff,0xfe,0x0a]));
    assert.equal(d.inspect().journalState,'JOURNAL_INVALID');
  });
});
test('directory chmod after construction fails closed with no mutation',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw]);
    const d=f.diag();
    fs.chmodSync(f.intake,0o777);
    try {
      const out=d.inspect();hold(out);
      assert.equal(out.result,'NOT_VERIFIED');
      assert.equal(out.reason,'GUARDIAN_DIAG_DIRECTORY_UNVERIFIED');
    } finally {fs.chmodSync(f.intake,0o700);}
  });
});
test('simulated lock replacement during journal read is a race, not approval',async()=>{
  await temp(async f=>{
    const raw=f.input();f.writer().intakeMany([raw]);
    fs.writeFileSync(f.lock,'locked',{mode:0o600});
    const d=f.diag();
    const original=fs.readSync;
    let mutated=false;
    try {
      fs.readSync=function(...args){
        const n=original.apply(this,args);
        if (!mutated) {
          mutated=true;
          fs.writeFileSync(f.lock,'changed-while-reading');
        }
        return n;
      };
      const out=d.inspect();
      hold(out);
      assert.equal(mutated,true);
      assert.equal(out.reason,'GUARDIAN_DIAG_CHANGED_DURING_READ');
      assert.equal(out.result,'NOT_VERIFIED');
    } finally {fs.readSync=original;}
  });
});
test('hostile config and nonregular directory are rejected without reading journal',async()=>{
  await temp(async f=>{
    for (const opts of [
      {fileName:'../other.jsonl'},
      {directory:'relative/path'},
      {maxJournalBytes:0},
      {maxJournalBytes:2**31},
      {extraneous:'DO_NOT_LOG'},
    ]) assert.throws(()=>f.diag(opts));
    assert.throws(()=>createGuardianCaseworkDiagnostics(
      new Proxy({}, {ownKeys(){throw Error('PRIVATE_TOKEN');}})),
      /GUARDIAN_CASEWORK_DIAGNOSTICS_CONFIG_INVALID/);
    const fake=path.join(f.root,'not-a-dir');
    fs.writeFileSync(fake,'');
    assert.throws(()=>f.diag({directory:fake}),
      /GUARDIAN_CASEWORK_DIAGNOSTICS_DIRECTORY_UNVERIFIED/);
  });
});
