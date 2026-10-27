'use strict';
// G28A: offline, disposable-only local append integrity regressions.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGuardianLocalReceiptJournal } =
  require('../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const NAME = 'guardian-writer-identity.jsonl';
const SUCCESS = Object.freeze({
  state:'STOPPED',errorCode:null,hostStopped:true,
  activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false,
});
const FAULT = Object.freeze({
  state:'FAILED',errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',
  hostStopped:false,activationAllowed:false,
  releaseAuthority:'NOT_ISSUED',automaticRestartAllowed:false,
});
function sandbox(fn) {
  const base=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-journal-anchor-'));
  try {
    const directory=path.join(base,'owner');
    fs.mkdirSync(directory,{mode:0o700});
    return fn({base,directory,target:path.join(directory,NAME)});
  } finally {
    fs.rmSync(base,{recursive:true,force:true});
  }
}
function writer(directory) {
  return createGuardianLocalReceiptJournal({directory,fileName:NAME});
}
function failed(write) {
  assert.throws(write,{code:'GUARDIAN_JOURNAL_WRITE_FAILED'});
}
function originalLines(target) {
  return fs.readFileSync(target,'utf8').trimEnd().split('\n').map(JSON.parse);
}

test('G28A construction inert; owner journal writes two append-only terminal records',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    assert.equal(fs.existsSync(target),false);
    assert.deepEqual(Object.keys(j),['append','recordLaunch','recordReady']);
    assert.ok(Object.isFrozen(j));
    assert.equal(j.append(SUCCESS).releaseAuthority,'NOT_ISSUED');
    const before=fs.readFileSync(target);
    assert.equal(j.append(FAULT).releaseAuthority,'NOT_ISSUED');
    const after=fs.readFileSync(target);
    assert.ok(after.subarray(0,before.length).equals(before));
    const rows=originalLines(target);
    assert.deepEqual(rows.map(x=>x.state),['STOPPED','FAILED']);
    assert.equal(new Set(rows.map(x=>x.eventId)).size,2);
    assert.equal(fs.statSync(target).mode&0o077,0);
  });
});

test('G28A post-construction directory permission weakening blocks creation',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    fs.chmodSync(directory,0o755);
    failed(()=>j.append(SUCCESS));
    assert.equal(fs.existsSync(target),false);
  });
});

test('G28A same-path owner directory inode replacement never creates a fresh log',()=>{
  sandbox(({base,directory,target})=>{
    const j=writer(directory);
    const saved=path.join(base,'saved-owner');
    fs.renameSync(directory,saved);
    fs.mkdirSync(directory,{mode:0o700});
    failed(()=>j.append(SUCCESS));
    assert.equal(fs.existsSync(target),false);
    assert.equal(fs.existsSync(path.join(saved,NAME)),false);
  });
});

test('G28A configured symlink alias cannot be redirected between construction and append',()=>{
  sandbox(({base,directory,target})=>{
    const second=path.join(base,'second');
    fs.mkdirSync(second,{mode:0o700});
    const alias=path.join(base,'owner-alias');
    fs.symlinkSync(directory,alias);
    const j=writer(alias);
    fs.unlinkSync(alias);
    fs.symlinkSync(second,alias);
    failed(()=>j.append(SUCCESS));
    assert.equal(fs.existsSync(target),false);
    assert.equal(fs.existsSync(path.join(second,NAME)),false);
  });
});

test('G28A hardlinked journal fails closed and neither linked pathname changes',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    j.append(SUCCESS);
    const other=path.join(directory,'backup-hardlink');
    fs.linkSync(target,other);
    const baseline=fs.readFileSync(target);
    failed(()=>j.append(FAULT));
    assert.ok(fs.readFileSync(target).equals(baseline));
    assert.ok(fs.readFileSync(other).equals(baseline));
  });
});

test('G28A preexisting hardlink blocks first append from a new writer',()=>{
  sandbox(({directory,target})=>{
    fs.writeFileSync(target,Buffer.from('preexisting\n'),{mode:0o600});
    const other=path.join(directory,'linked');
    fs.linkSync(target,other);
    const j=writer(directory);
    failed(()=>j.append(SUCCESS));
    assert.equal(fs.readFileSync(target,'utf8'),'preexisting\n');
  });
});

test('G28A truncated final JSONL line is preserved and not silently extended',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    j.append(SUCCESS);
    const previous=fs.readFileSync(target);
    fs.truncateSync(target,previous.length-1);
    const partial=fs.readFileSync(target);
    failed(()=>j.append(FAULT));
    assert.ok(fs.readFileSync(target).equals(partial));
  });
});

test('G28A preexisting partial line blocks even the first append',()=>{
  sandbox(({directory,target})=>{
    fs.writeFileSync(target,Buffer.from('{"partial":true}', 'utf8'),{mode:0o600});
    const j=writer(directory);
    failed(()=>j.append(SUCCESS));
    assert.equal(fs.readFileSync(target,'utf8'),'{"partial":true}');
  });
});

test('G28A deleting journal after a successful append cannot reset in-memory origin',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    j.append(SUCCESS);
    fs.unlinkSync(target);
    failed(()=>j.append(FAULT));
    assert.equal(fs.existsSync(target),false);
  });
});

test('G28A byte-identical journal replacement with a new inode is rejected',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    j.append(SUCCESS);
    const previous=fs.readFileSync(target);
    const replacement=path.join(directory,'replacement');
    fs.writeFileSync(replacement,previous,{mode:0o600});
    fs.renameSync(replacement,target);
    failed(()=>j.append(FAULT));
    assert.ok(fs.readFileSync(target).equals(previous));
  });
});

test('G28A symlink substitution rejects before writing through to other files',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    j.append(SUCCESS);
    const original=fs.readFileSync(target);
    const victim=path.join(directory,'unrelated-private');
    fs.writeFileSync(victim,Buffer.from('CONFIDENTIAL\n'),{mode:0o600});
    fs.unlinkSync(target);
    fs.symlinkSync(victim,target);
    failed(()=>j.append(FAULT));
    assert.equal(fs.readFileSync(victim,'utf8'),'CONFIDENTIAL\n');
    assert.equal(fs.lstatSync(target).isSymbolicLink(),true);
    assert.ok(original.length>0);
  });
});

test('G28A permissive target journal fails closed even if directory is safe',()=>{
  sandbox(({directory,target})=>{
    const j=writer(directory);
    j.append(SUCCESS);
    const before=fs.readFileSync(target);
    fs.chmodSync(target,0o644);
    failed(()=>j.append(FAULT));
    assert.ok(fs.readFileSync(target).equals(before));
  });
});

test('G35 same-inode truncation at a complete JSONL row is rejected', () => {
  sandbox(({directory, target}) => {
    const j = writer(directory);
    j.append(SUCCESS);
    j.append(FAULT);
    const full = fs.readFileSync(target);
    const boundary = full.indexOf(10) + 1;
    assert.ok(boundary > 0 && boundary < full.length);
    fs.truncateSync(target, boundary);
    const truncated = fs.readFileSync(target);
    failed(() => j.append(SUCCESS));
    assert.ok(fs.readFileSync(target).equals(truncated));
  });
});

test('G35 same-inode same-size rewrite of valid receipt is rejected', () => {
  sandbox(({directory, target}) => {
    const j = writer(directory);
    j.append(FAULT);
    const original = fs.readFileSync(target, 'utf8');
    const eventId = JSON.parse(original).eventId;
    const changedId = (eventId[0] === 'a' ? 'b' : 'a') + eventId.slice(1);
    const changed = Buffer.from(original.replace(eventId, changedId));
    assert.equal(changed.length, Buffer.byteLength(original));
    const fd = fs.openSync(target, 'r+');
    try {
      assert.equal(fs.writeSync(fd, changed, 0, changed.length, 0),
        changed.length);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    assert.equal(JSON.parse(fs.readFileSync(target, 'utf8')).eventId, changedId);
    failed(() => j.append(SUCCESS));
    assert.ok(fs.readFileSync(target).equals(changed));
  });
});

test('G35 unexpected external full-row append is not silently trusted', () => {
  sandbox(({directory, target}) => {
    const j = writer(directory);
    j.append(SUCCESS);
    const known = fs.readFileSync(target);
    fs.appendFileSync(target, known);
    const unexpected = fs.readFileSync(target);
    failed(() => j.append(FAULT));
    assert.ok(fs.readFileSync(target).equals(unexpected));
  });
});

test('G35 new writer instance can append an existing intact journal', () => {
  sandbox(({directory, target}) => {
    writer(directory).append(SUCCESS);
    const previous = fs.readFileSync(target);
    writer(directory).append(FAULT);
    const updated = fs.readFileSync(target);
    assert.ok(updated.subarray(0, previous.length).equals(previous));
    assert.deepEqual(originalLines(target).map(x => x.state),
      ['STOPPED', 'FAILED']);
  });
});
