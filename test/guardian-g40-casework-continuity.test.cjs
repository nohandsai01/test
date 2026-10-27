'use strict';
// G40: Owner-only local casework append continuity. Synthetic temp files only.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {createGuardianOfflineCasework}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-casework.cjs');

function fixture(run) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-g40-'));
  const dir=path.join(root,'casework');
  fs.mkdirSync(dir,{mode:0o700});
  const fileName='guardian-g40-casework.jsonl';
  const file=path.join(dir,fileName), lock=file+'.lock';
  const make=()=>createGuardianOfflineCasework({directory:dir,fileName});
  try {run({dir,file,lock,make});}
  finally {fs.rmSync(root,{recursive:true,force:true});}
}
function record(writer) {
  const result=writer.intakeMany(['NOT_AN_OFFLINE_BRIEF']);
  assert.equal(result.status,'SOURCE_ONLY_HOLD');
  assert.equal(result.decision,'LOCAL_RECORD_ONLY');
  assert.equal(result.entries.length,1);
  assert.equal(result.entries[0].decision,'REJECTED');
  return result;
}
function rejected(writer) {
  const r=writer.intakeMany(['NOT_AN_OFFLINE_BRIEF']);
  assert.equal(r.status,'SOURCE_ONLY_HOLD');
  assert.equal(r.decision,'NOT_VERIFIED');
  assert.equal(r.entries.length,0);
}
function rewriteFirstId(file) {
  const rows=fs.readFileSync(file,'utf8').trim().split('\n');
  const first=JSON.parse(rows[0]);
  first.id=crypto.randomUUID();
  rows[0]=JSON.stringify(first);
  fs.writeFileSync(file,rows.join('\n')+'\n',{mode:0o600});
}

test('G40 initial and consecutive casework writes remain append-only and inert',()=>{
  fixture(f=>{
    const writer=f.make();
    assert.equal(fs.existsSync(f.file),false);
    record(writer);
    const original=fs.readFileSync(f.file);
    record(writer);
    assert.equal(fs.readFileSync(f.file).subarray(0,original.length)
      .equals(original),true);
    const q=writer.exceptions();
    assert.equal(q.decision,'LOCAL_RECORD_ONLY');
    assert.equal(q.entries.length,2);
    assert.equal(fs.existsSync(f.lock),false);
  });
});
test('G40 same-inode equal-length valid receipt edit latches failure',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    const before=fs.statSync(f.file);
    const clean=fs.readFileSync(f.file);
    rewriteFirstId(f.file);
    const altered=fs.readFileSync(f.file);
    assert.equal(fs.statSync(f.file).ino,before.ino);
    assert.equal(altered.length,clean.length);
    assert.notDeepEqual(altered,clean);
    rejected(writer);
    assert.deepEqual(fs.readFileSync(f.file),altered);
    fs.writeFileSync(f.file,clean);
    rejected(writer);
  });
});
test('G40 whole-record truncation rejects without manufacturing a replacement baseline',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    fs.truncateSync(f.file,0);
    rejected(writer);
    assert.equal(fs.statSync(f.file).size,0);
    assert.equal(fs.existsSync(f.lock),false);
  });
});
test('G40 deleted witnessed casework journal is not recreated via O_CREAT',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    fs.unlinkSync(f.file);
    rejected(writer);
    assert.equal(fs.existsSync(f.file),false);
    assert.equal(fs.existsSync(f.lock),false);
  });
});
test('G40 new inode containing identical receipts cannot substitute journal',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    const bytes=fs.readFileSync(f.file);
    const original=fs.statSync(f.file).ino;
    const replacement=f.file+'.replacement';
    fs.writeFileSync(replacement,bytes,{mode:0o600});
    fs.renameSync(replacement,f.file);
    assert.notEqual(fs.statSync(f.file).ino,original);
    rejected(writer);
    assert.deepEqual(fs.readFileSync(f.file),bytes);
  });
});
test('G40 independent local writer append invalidates stale witnessed history',()=>{
  fixture(f=>{
    const first=f.make(),second=f.make();
    record(first);
    record(second);
    const accepted=fs.readFileSync(f.file);
    rejected(first);
    assert.deepEqual(fs.readFileSync(f.file),accepted);
    assert.equal(fs.existsSync(f.lock),false);
  });
});
test('G40 in-place rewrite during fsync cannot pass post-write byte verification',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    const originalFsync=fs.fsyncSync;
    let injected=false;
    try {
      fs.fsyncSync=function(fd) {
        originalFsync.call(fs,fd);
        if (!injected) {
          injected=true;
          rewriteFirstId(f.file);
        }
      };
      rejected(writer);
    } finally {fs.fsyncSync=originalFsync;}
    assert.equal(injected,true);
    assert.equal(fs.existsSync(f.lock),true);
  });
});
test('G40 pathname replacement after fsync keeps uncertain-write lock',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    const originalFsync=fs.fsyncSync;
    let injected=false;
    try {
      fs.fsyncSync=function(fd) {
        originalFsync.call(fs,fd);
        if (!injected) {
          injected=true;
          const swap=f.file+'.swap';
          fs.writeFileSync(swap,fs.readFileSync(f.file),{mode:0o600});
          fs.renameSync(swap,f.file);
        }
      };
      rejected(writer);
    } finally {fs.fsyncSync=originalFsync;}
    assert.equal(injected,true);
    assert.equal(fs.existsSync(f.lock),true);
  });
});
test('G40 a new writer can read a valid historical journal but cannot attest its past',()=>{
  fixture(f=>{
    record(f.make());
    const fresh=f.make();
    record(fresh);
    assert.equal(fs.readFileSync(f.file,'utf8').trim().split('\n').length,2);
  });
});
test('G40 read-only exceptions cannot report deleted witnessed history as no journal',()=>{
  fixture(f=>{
    const writer=f.make();
    assert.equal(writer.exceptions().reason,'GUARDIAN_CASEWORK_EXCEPTIONS_NO_JOURNAL');
    record(writer);
    fs.unlinkSync(f.file);
    const seen=writer.exceptions();
    assert.equal(seen.status,'SOURCE_ONLY_HOLD');
    assert.equal(seen.decision,'NOT_VERIFIED');
    assert.notEqual(seen.reason,'GUARDIAN_CASEWORK_EXCEPTIONS_NO_JOURNAL');
    assert.equal(fs.existsSync(f.file),false);
    rejected(writer);
  });
});
test('G40 malformed journal on read latches hold after initial valid observation',()=>{
  fixture(f=>{
    const writer=f.make();
    record(writer);
    const original=fs.readFileSync(f.file);
    fs.appendFileSync(f.file,'INVALID_JSON\n');
    const seen=writer.exceptions();
    assert.equal(seen.decision,'NOT_VERIFIED');
    fs.writeFileSync(f.file,original);
    assert.equal(writer.exceptions().decision,'NOT_VERIFIED');
    rejected(writer);
  });
});
