'use strict';
// G27E offline owner-only casework. Synthetic local files and no real D1/App.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const { createGuardianOfflineCasework }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-casework.cjs');
const { createGuardianLocalReceiptJournal }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const { createGuardianLocalOperatorSession }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianOfflineIncidentBrief }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { makeBundle }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-brief-verifier.cjs');

const worker=path.join(__dirname,'guardian-protected-worker-child.cjs');
const stopped={state:'STOPPED',errorCode:null,hostStopped:true,
  activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false};
const failed={state:'FAILED',errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',
  hostStopped:false,activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false};
async function fixture(callback) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-casework-'));
  const source=path.join(root,'source'), inbox=path.join(root,'inbox');
  fs.mkdirSync(source,{mode:0o700});fs.mkdirSync(inbox,{mode:0o700});
  const fileName='guardian-casework.jsonl';
  const journal=createGuardianLocalReceiptJournal({
    directory:source,fileName:'guardian-source.jsonl',
  });
  const session=createGuardianLocalOperatorSession({
    cwd:path.dirname(worker),entrypoint:worker,
    directory:source,fileName:'guardian-source.jsonl',
  });
  const capture=()=>createGuardianOfflineIncidentBrief({
    operator:session.operator,limit:10,
  }).capture();
  const makeInput=()=>{
    journal.append(stopped);
    const a=capture();
    journal.append(failed);
    const b=capture();
    return JSON.stringify(makeBundle([a,b]));
  };
  const make= (options={})=>createGuardianOfflineCasework({
    directory:inbox,fileName,...options,
  });
  const rows=()=>{
    const target=path.join(inbox,fileName);
    return fs.existsSync(target)?
      fs.readFileSync(target,'utf8').trim().split('\n')
        .filter(Boolean).map(JSON.parse):[];
  };
  try {await callback({root,source,inbox,journal,capture,makeInput,make,rows,
    fileName,log:path.join(inbox,fileName),lock:path.join(inbox,fileName+'.lock')});}
  finally {fs.rmSync(root,{recursive:true,force:true});}
}
function hold(r) {
  assert.equal(r.status,'SOURCE_ONLY_HOLD');
  assert.equal(r.releaseAuthority,'NOT_ISSUED');
  assert.equal(r.activationAllowed,false);
  assert.equal(r.automaticRestartAllowed,false);
  assert.equal(r.custodyVerified,false);
  assert.equal(r.manualInterventionRequired,true);
  assert.equal(r.liveness,'NOT_PROVEN');
  assert.ok(Object.isFrozen(r));
  assert.ok(Object.isFrozen(r.entries));
  for (const name of ['pid','privateKey','token','rawBundle',
    'clearHold','restart','issueCheck']) {
    assert.equal(Object.hasOwn(r,name),false);
  }
}
function intake(m,raw) {
  const result=m.intakeMany([raw]);
  hold(result);
  assert.equal(result.decision,'LOCAL_RECORD_ONLY');
  assert.equal(result.entries.length,1);
  return result.entries[0];
}
test('construction inert, frozen capabilities and missing-journal exception query',async()=>{
  await fixture(async f=>{
    const c=f.make();
    assert.ok(Object.isFrozen(c));
    assert.deepEqual(Object.keys(c).sort(),
      ['intakeMany','handoff','exceptions'].sort());
    assert.deepEqual(fs.readdirSync(f.inbox),[]);
    const r=c.exceptions();
    hold(r);
    assert.equal(r.reason,'GUARDIAN_CASEWORK_EXCEPTIONS_NO_JOURNAL');
    assert.equal(r.entries.length,0);
    assert.deepEqual(fs.readdirSync(f.inbox),[]);
  });
});
test('two identical bundles in one batch quarantine once and record duplicate reference',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput();
    const result=f.make().intakeMany([raw,raw]);
    hold(result);
    assert.equal(result.decision,'LOCAL_RECORD_ONLY');
    assert.equal(result.entries.length,2);
    const [a,b]=result.entries;
    assert.equal(a.decision,'QUARANTINED');
    assert.equal(b.decision,'DUPLICATE');
    assert.equal(b.originalId,a.id);
    assert.equal(b.bundleSha256,a.bundleSha256);
    assert.equal(f.rows().length,2);
    assert.equal(f.rows()[1].originalId,a.id);
    const q=f.make().exceptions();
    hold(q);
    assert.equal(q.entries.length,1);
    assert.equal(q.entries[0].decision,'DUPLICATE');
    assert.equal(q.entries[0].originalId,a.id);
    assert.match(q.journalSha256,/^[0-9a-f]{64}$/);
    assert.ok(!fs.readFileSync(f.log,'utf8').includes('"events"'));
  });
});
test('cross-instance repeated bundle stays duplicate and never changes original quarantine ID',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput();
    const first=intake(f.make(),raw);
    const second=intake(f.make(),raw);
    const third=intake(f.make(),raw);
    assert.equal(first.decision,'QUARANTINED');
    assert.equal(second.decision,'DUPLICATE');
    assert.equal(third.decision,'DUPLICATE');
    assert.equal(second.originalId,first.id);
    assert.equal(third.originalId,first.id);
    assert.equal(f.rows().length,3);
  });
});
test('distinct checksum-valid bundles remain distinct quarantines',async()=>{
  await fixture(async f=>{
    const older=f.makeInput();
    f.journal.append(stopped);
    const a=f.capture();
    f.journal.append(failed);
    const b=f.capture();
    const newer=JSON.stringify(makeBundle([a,b]));
    const r=f.make().intakeMany([older,newer]);
    hold(r);
    assert.deepEqual(r.entries.map(x=>x.decision),
      ['QUARANTINED','QUARANTINED']);
    assert.equal(f.rows().length,2);
    assert.notEqual(r.entries[0].bundleSha256,r.entries[1].bundleSha256);
  });
});
test('corrupt, duplicate JSON, reversed history and invalid input are rejected safely',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput();
    const cases=[
      [raw.replace('"count":2','"count":2,"count":2'),'GUARDIAN_CASEWORK_INPUT_INVALID'],
      [raw.replace('"bundleSha256":"','"bundleSha256":"x'),'GUARDIAN_CASEWORK_BUNDLE_INVALID'],
      [raw+' trailing secret','GUARDIAN_CASEWORK_INPUT_INVALID'],
      ['', 'GUARDIAN_CASEWORK_INPUT_INVALID'],
      [{token:'PRIVATE'},'GUARDIAN_CASEWORK_INPUT_INVALID'],
      [Buffer.from(raw),'GUARDIAN_CASEWORK_INPUT_INVALID'],
    ];
    const result=f.make().intakeMany(cases.map(x=>x[0]));
    hold(result);
    assert.deepEqual(result.entries.map(x=>x.decision),cases.map(()=>'REJECTED'));
    assert.deepEqual(result.entries.map(x=>x.reason),cases.map(x=>x[1]));
    assert.equal(f.rows().length,cases.length);
    assert.ok(!fs.readFileSync(f.log,'utf8').includes('PRIVATE'));
  });
});
test('manual handoff remains a local annotation with explicit transition rules',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make();
    const record=intake(cw,raw);
    let r=cw.handoff({receiptId:record.id,transition:'REQUESTED'});
    hold(r);
    assert.equal(r.decision,'LOCAL_RECORD_ONLY');
    assert.equal(r.entries[0].transition,'REQUESTED');
    const again=cw.handoff({receiptId:record.id,transition:'REQUESTED'});
    hold(again);
    assert.equal(again.decision,'NOT_VERIFIED');
    assert.equal(again.reason,'GUARDIAN_CASEWORK_HANDOFF_TRANSITION_INVALID');
    r=cw.handoff({receiptId:record.id,transition:'ACKNOWLEDGED'});
    assert.equal(r.entries[0].transition,'ACKNOWLEDGED');
    r=cw.handoff({receiptId:record.id,transition:'RETURNED'});
    assert.equal(r.entries[0].transition,'RETURNED');
    r=cw.handoff({receiptId:record.id,transition:'REQUESTED'});
    assert.equal(r.entries[0].transition,'REQUESTED');
    assert.equal(f.rows().length,5);
    assert.ok(f.rows().every(x=>x.kind==='GUARDIAN_CASEWORK_RECEIPT_V1'));
    const query=cw.exceptions();
    assert.equal(query.entries[0].transition,'RETURNED');
    assert.equal(query.entries[0].subjectId,record.id);
  });
});
test('handoff cannot act on duplicate, rejected or unknown receipt',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make();
    const [first,duplicate]=cw.intakeMany([raw,raw]).entries;
    const invalid = f.rows().filter(x=>x.decision==='DUPLICATE')[0];
    assert.equal(duplicate.id,invalid.id);
    for (const id of [duplicate.id,'00000000-0000-4000-8000-000000000001']) {
      const r=cw.handoff({receiptId:id,transition:'REQUESTED'});
      hold(r);
      assert.equal(r.decision,'NOT_VERIFIED');
    }
    assert.equal(cw.handoff({receiptId:first.id,transition:'ACKNOWLEDGED'})
      .decision,'NOT_VERIFIED');
    assert.equal(f.rows().length,2);
  });
});
test('rejection/duplicate/RETURNED exception pagination supports stale cursor',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make();
    cw.intakeMany([raw,raw,raw]);
    const earlier=cw.exceptions({limit:1});
    hold(earlier);
    assert.equal(earlier.entries.length,1);
    assert.equal(earlier.entries[0].decision,'DUPLICATE');
    assert.ok(earlier.nextCursor);
    const older=cw.exceptions({limit:3,cursor:earlier.nextCursor});
    assert.equal(older.entries.length,1);
    const digest=earlier.journalSha256;
    cw.intakeMany([raw]);
    const stale=cw.exceptions({cursor:earlier.nextCursor});
    hold(stale);
    assert.equal(stale.decision,'NOT_VERIFIED');
    assert.equal(stale.reason,'GUARDIAN_CASEWORK_CURSOR_STALE');
    assert.equal(stale.entries.length,0);
    assert.notEqual(cw.exceptions().journalSha256,digest);
  });
});
test('casework rejects truncated, duplicate key and mismatched journal without accepting more',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make();
    cw.intakeMany([raw]);
    const bytes=fs.readFileSync(f.log);
    const scenarios=[
      bytes.subarray(0,bytes.length-1),
      Buffer.from(bytes.toString('utf8').replace('"schemaVersion":1,',
        '"schemaVersion":1,"schemaVersion":1,')),
      Buffer.from(bytes.toString('utf8').replace(
        '"kind":"GUARDIAN_CASEWORK_RECEIPT_V1"',
        '"kind":"GUARDIAN_CASEWORK_FAKE_V1"')),
    ];
    for (const data of scenarios) {
      assert.equal(data.equals(bytes),false,'negative case must mutate actual bytes');
      fs.writeFileSync(f.log,data);
      const outcome=cw.intakeMany([raw]);
      hold(outcome);
      assert.equal(outcome.decision,'NOT_VERIFIED');
      const listing=cw.exceptions();
      hold(listing);
      assert.equal(listing.decision,'NOT_VERIFIED');
    }
  });
});
test('existing manual lock or symlink journal blocks writes (no stale lock auto-healing)',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make();
    fs.writeFileSync(f.lock,'synthetic-in-progress',{mode:0o600});
    const blocked=cw.intakeMany([raw]);
    hold(blocked);
    assert.equal(blocked.decision,'NOT_VERIFIED');
    assert.equal(fs.existsSync(f.log),false);
    assert.equal(fs.readFileSync(f.lock,'utf8'),'synthetic-in-progress');
    fs.unlinkSync(f.lock);
    fs.symlinkSync('/dev/null',f.log);
    const other=cw.intakeMany([raw]);
    hold(other);
    assert.equal(other.decision,'NOT_VERIFIED');
    assert.ok(fs.lstatSync(f.log).isSymbolicLink());
  });
});
test('journal cap rejects whole multi-item batch before writing a partial batch',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make({maxJournalBytes:1024});
    const r=cw.intakeMany(Array(8).fill(raw));
    hold(r);
    assert.equal(r.decision,'NOT_VERIFIED');
    assert.equal(fs.existsSync(f.log)?fs.statSync(f.log).size:0,0);
    assert.equal(fs.existsSync(f.lock),false);
  });
});
test('unsafe owner directory and journal permissions fail closed',async()=>{
  await fixture(async f=>{
    const raw=f.makeInput(),cw=f.make();
    fs.chmodSync(f.inbox,0o777);
    try{
      assert.equal(cw.intakeMany([raw]).decision,'NOT_VERIFIED');
      assert.equal(cw.exceptions().decision,'NOT_VERIFIED');
      assert.throws(()=>f.make(),/GUARDIAN_CASEWORK_DIRECTORY_UNVERIFIED/);
    }finally{fs.chmodSync(f.inbox,0o700);}
    cw.intakeMany([raw]);
    fs.chmodSync(f.log,0o644);
    assert.equal(cw.intakeMany([raw]).decision,'NOT_VERIFIED');
    assert.equal(cw.exceptions().decision,'NOT_VERIFIED');
  });
});
test('bad options and malicious cursors reject without source mutation',async()=>{
  await fixture(async f=>{
    for (const options of [
      {fileName:'../data.jsonl'},{directory:'relative/path'},
      {maxJournalBytes:-1},{maxJournalBytes:Infinity},{other:'token'},
    ]) assert.throws(()=>f.make(options));
    const cw=f.make();
    for (const x of [[],null,{},new Array(2),Array(9).fill('x')]) {
      const r=cw.intakeMany(x);
      hold(r);
      assert.equal(r.decision,'NOT_VERIFIED');
    }
    for (const params of [{limit:0},{limit:30},
      {cursor:{sha:'wrong',before:1}},
      {cursor:{sha:'a'.repeat(64),before:0}},
      {unknown:true}]) {
      const r=cw.exceptions(params);hold(r);
      assert.equal(r.decision,'NOT_VERIFIED');
    }
    assert.equal(fs.existsSync(f.log),false);
  });
});


test('real separate Node process cannot bypass an existing per-journal lock',async()=>{
  const {spawnSync}=require('node:child_process');
  await fixture(async f=>{
    const raw=f.makeInput();
    const modulePath=path.join(__dirname,
      '../merge-gate-install/guardian-candidate/guardian-local-offline-casework.cjs');
    const script=[
      'const {createGuardianOfflineCasework}=require(process.argv[1]);',
      'const c=createGuardianOfflineCasework({directory:process.argv[2],fileName:process.argv[3]});',
      'const result=c.intakeMany([process.argv[4]]);',
      'process.stdout.write(JSON.stringify({decision:result.decision,reason:result.reason}));',
    ].join('');
    fs.writeFileSync(f.lock,'pending-owner',{mode:0o600});
    const run=()=>spawnSync(process.execPath,['-e',script,
      modulePath,f.inbox,f.fileName,raw],{
      encoding:'utf8',timeout:2500,
      env:{NODE_ENV:'test',PATH:'/usr/bin:/bin'},
    });
    const blocked=run();
    assert.equal(blocked.status,0,blocked.stderr);
    assert.equal(JSON.parse(blocked.stdout).decision,'NOT_VERIFIED');
    assert.equal(fs.existsSync(f.log),false);
    assert.equal(fs.readFileSync(f.lock,'utf8'),'pending-owner');
    fs.unlinkSync(f.lock);
    const first=run();
    assert.equal(first.status,0,first.stderr);
    assert.equal(JSON.parse(first.stdout).decision,'LOCAL_RECORD_ONLY');
    const repeated=run();
    assert.equal(repeated.status,0,repeated.stderr);
    assert.equal(JSON.parse(repeated.stdout).decision,'LOCAL_RECORD_ONLY');
    assert.deepEqual(f.rows().map(r=>r.decision),['QUARANTINED','DUPLICATE']);
  });
});
test('hostile query options reject without touching the durable journal',async()=>{
  await fixture(async f=>{
    const cw=f.make();
    for(const evil of [
      new Proxy({}, {ownKeys(){throw new Error('PRIVATE_TOKEN');}}),
      Object.defineProperty({},'limit',{get(){throw new Error('SECRET');},
        enumerable:true}),
      {limit:1,extra:Symbol('secret')},
    ]) {
      const r=cw.exceptions(evil);
      hold(r);
      assert.equal(r.decision,'NOT_VERIFIED');
      assert.ok(!JSON.stringify(r).includes('SECRET'));
    }
    assert.equal(fs.existsSync(f.log),false);
    assert.throws(()=>createGuardianOfflineCasework(
      new Proxy({}, {ownKeys(){throw Error('SECRET');}})),
      /GUARDIAN_CASEWORK_CONFIG_INVALID/);
  });
});
