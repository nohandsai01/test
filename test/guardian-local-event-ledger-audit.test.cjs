'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {createGuardianLocalLedgerAudit}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-event-ledger-audit.cjs');
const {createGuardianLocalDiagnostics}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-diagnostics.cjs');
const {createGuardianLocalReceiptJournal}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');
const {createGuardianLocalOperatorSession}=require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const worker=path.join(__dirname,'guardian-protected-worker-child.cjs');

async function withTemp(fn) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-ledger-audit-'));
  try {return await fn(dir);}
  finally {fs.rmSync(dir,{force:true,recursive:true});}
}
function writer(dir) {
  return createGuardianLocalReceiptJournal({
    directory:dir,fileName:'guardian-audit-events.jsonl',
  });
}
function stop() {
  return {state:'STOPPED',errorCode:null,hostStopped:true,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    automaticRestartAllowed:false};
}
function fail(code='GUARDIAN_CHILD_EXIT_UNVERIFIED') {
  return {state:'FAILED',errorCode:code,hostStopped:false,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    automaticRestartAllowed:false};
}
function diagnostic(dir,state='STOPPED',status) {
  return createGuardianLocalDiagnostics({
    directory:dir,fileName:'guardian-audit-events.jsonl',
    controller:{status:status||(()=>({
      state,activationAllowed:false,
      releaseAuthority:'NOT_ISSUED',automaticRestartAllowed:false,
    }))},
  });
}
function audit(operator,pageSize=5,maxCaptureMs=5000) {
  return createGuardianLocalLedgerAudit({operator,pageSize,maxCaptureMs});
}
function hold(result) {
  assert.equal(result.status,'SOURCE_ONLY_HOLD');
  assert.equal(result.authority,'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(result.liveness,'NOT_PROVEN');
  assert.equal(result.manualInterventionRequired,true);
  assert.equal(result.automaticRestartAllowed,false);
  assert.equal(result.activationAllowed,false);
  assert.equal(result.releaseAuthority,'NOT_ISSUED');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.failureCodes));
}
function raw(dir) {
  return fs.readFileSync(path.join(dir,'guardian-audit-events.jsonl'),'utf8')
    .trimEnd().split('\n').map(JSON.parse);
}
function expectedTimelineHash(rows) {
  const sha=crypto.createHash('sha256');
  for(const e of [...rows].reverse()) {
    sha.update(JSON.stringify({eventId:e.eventId,timestamp:e.timestamp,
      state:e.state,errorCode:e.errorCode})+'\n');
  }
  return sha.digest('hex');
}

test('inert constructor and missing-journal capture do not create an artifact',async()=>{
  await withTemp(async(dir)=>{
    const d=diagnostic(dir,'CREATED');
    let reads=0;
    const c=audit({recentEvents(o){reads++;return d.recentEvents(o);}},3);
    assert.equal(reads,0);
    assert.deepEqual(fs.readdirSync(dir),[]);
    assert.deepEqual(Object.keys(c),['capture']);
    const result=c.capture();
    hold(result);
    assert.equal(reads,1);
    assert.equal(result.comparison,'NOT_VERIFIED');
    assert.equal(result.reason,'GUARDIAN_LEDGER_PAGE_UNVERIFIED');
    assert.equal(result.orderedEventsSha256,null);
    assert.equal(result.inspectedEntries,0);
    assert.deepEqual(result.failureCodes,[]);
    assert.deepEqual(fs.readdirSync(dir),[]);
  });
});

test('complete journal pages exactly once, hash chronological order and never leak raw record fields',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<13;i++) j.append(stop());
    const before=fs.readFileSync(path.join(dir,'guardian-audit-events.jsonl'));
    const d=diagnostic(dir);
    const operator={recentEvents:o=>d.recentEvents(o),start(){
      throw Error('SHOULD_NOT_START');
    },stop(){throw Error('SHOULD_NOT_STOP');}};
    const c=audit(operator,5);
    const first=c.capture(),second=c.capture();
    hold(first);
    assert.equal(first.comparison,'MATCH_LOCAL_PAGES_ONLY');
    assert.equal(first.reason,'GUARDIAN_LEDGER_COMPLETE_LOCAL');
    assert.equal(first.inspectedEntries,13);
    assert.equal(first.inspectedPages,3);
    assert.equal(first.failureCount,0);
    assert.equal(first.firstFailure,null);
    assert.equal(first.latestFailure,null);
    assert.deepEqual(first.failureCodes,[]);
    assert.match(first.journalSha256,/^[a-f0-9]{64}$/);
    assert.equal(first.orderedEventsSha256,expectedTimelineHash(raw(dir)));
    assert.equal(first.orderedEventsSha256,second.orderedEventsSha256);
    assert.deepEqual(fs.readFileSync(path.join(dir,'guardian-audit-events.jsonl')),before);
    for(const field of ['pid','secret','rawJournal','controller','cursor',
      'readyForRelease','verifiedLiveness','entries']) {
      assert.equal(Object.hasOwn(first,field),false);
    }
  });
});

test('historical fault remains visible after subsequent clean receipts across multiple pages',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<120;i++) {
      j.append(i===4||i===118 ? fail('GUARDIAN_CHILD_EXIT_UNVERIFIED') :
        i===55 ? fail('GUARDIAN_CHILD_HEALTH_UNVERIFIED') : stop());
    }
    const rows=raw(dir), faults=rows.filter(e=>e.state==='FAILED');
    const result=audit(diagnostic(dir),17).capture();
    hold(result);
    assert.equal(result.comparison,'MATCH_LOCAL_PAGES_ONLY');
    assert.equal(result.inspectedEntries,120);
    assert.equal(result.inspectedPages,8);
    assert.equal(result.failureCount,3);
    assert.equal(result.firstFailure.eventId,faults[0].eventId);
    assert.equal(result.latestFailure.eventId,faults[2].eventId);
    assert.equal(result.lastTerminal.state,'STOPPED');
    assert.deepEqual(result.failureCodes,[
      {code:'GUARDIAN_CHILD_EXIT_UNVERIFIED',count:2},
      {code:'GUARDIAN_CHILD_HEALTH_UNVERIFIED',count:1},
    ]);
    assert.equal(result.orderedEventsSha256,expectedTimelineHash(rows));
  });
});

test('Owner and Operator remain strictly separated in actual local session',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    j.append(stop());j.append(fail());j.append(stop());
    const original=fs.readFileSync(path.join(dir,'guardian-audit-events.jsonl'));
    const session=createGuardianLocalOperatorSession({
      cwd:path.dirname(worker),entrypoint:worker,
      directory:dir,fileName:'guardian-audit-events.jsonl',
    });
    assert.equal(Object.hasOwn(session.operator,'start'),false);
    assert.equal(Object.hasOwn(session.operator,'stop'),false);
    const result=audit(session.operator,2).capture();
    hold(result);
    assert.equal(result.comparison,'MATCH_LOCAL_PAGES_ONLY');
    assert.equal(result.failureCount,1);
    assert.equal(result.inspectedPages,2);
    assert.deepEqual(fs.readFileSync(path.join(dir,'guardian-audit-events.jsonl')),original);
  });
});

test('append between pages returns no partial fault details',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<7;i++)j.append(i===2?fail():stop());
    const d=diagnostic(dir);
    let calls=0;
    const result=audit({recentEvents:options=>{
      const response=d.recentEvents(options);
      if(++calls===1)j.append(stop());
      return response;
    }},3).capture();
    hold(result);
    assert.equal(calls,2);
    assert.equal(result.comparison,'NOT_VERIFIED');
    assert.equal(result.reason,'GUARDIAN_LEDGER_PAGE_UNVERIFIED');
    assert.equal(result.journalSha256,null);
    assert.equal(result.orderedEventsSha256,null);
    assert.equal(result.inspectedEntries,0);
    assert.equal(result.firstFailure,null);
  });
});

test('changing controller state between pages is rejected',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<6;i++)j.append(stop());
    const d1=diagnostic(dir,'STOPPED'),d2=diagnostic(dir,'RUNNING');
    let calls=0;
    const result=audit({recentEvents(o){
      return ++calls===1?d1.recentEvents(o):d2.recentEvents(o);
    }},2).capture();
    hold(result);
    assert.equal(result.reason,'GUARDIAN_LEDGER_SNAPSHOT_CHANGED');
    assert.equal(result.inspectedEntries,0);
  });
});

test('truncated page, replayed cursor, and duplicate event IDs are rejected',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<7;i++)j.append(stop());
    const d=diagnostic(dir);
    const baseline=d.recentEvents({limit:3});
    const tests=[
      {change:(p)=>({...p,entries:p.entries.slice(0,2)}),
        reason:'GUARDIAN_LEDGER_PAGE_INCOMPLETE'},
      {change:(p)=>({...p,nextCursor:null}),
        reason:'GUARDIAN_LEDGER_CURSOR_INCONSISTENT'},
      {change:(p)=>({...p,nextCursor:{
        journalSha256:p.journalSha256,before:6}}),
        reason:'GUARDIAN_LEDGER_CURSOR_INCONSISTENT'},
      {change:(p)=>({...p,entries:Object.freeze([
        p.entries[0],p.entries[0],p.entries[2]])}),
        reason:'GUARDIAN_LEDGER_DUPLICATE_EVENT'},
    ];
    for(const item of tests) {
      let calls=0;
      const res=audit({recentEvents:o=>{
        const p=d.recentEvents(o);
        return ++calls===1?item.change(p):p;
      }},3).capture();
      hold(res);
      assert.equal(res.reason,item.reason);
      assert.equal(res.inspectedEntries,0);
    }
    assert.equal(baseline.entries.length,3);
  });
});

test('cross-page altered aggregate, terminal, cursor checksum fail closed',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<8;i++)j.append(i===2?fail():stop());
    const d=diagnostic(dir);
    const cases=[
      {change:p=>({...p,incident:{...p.incident,failureCount:2}}),
        reason:'GUARDIAN_LEDGER_SNAPSHOT_CHANGED'},
      {change:p=>({...p,lastTerminal:p.entries[0]}),
        reason:'GUARDIAN_LEDGER_SNAPSHOT_CHANGED'},
      {change:p=>({...p,journalSha256:'f'.repeat(64)}),
        reason:'GUARDIAN_LEDGER_PAGE_UNVERIFIED'},
      {change:p=>({...p,incident:{...p.incident,
        firstFailure:{...p.incident.firstFailure,eventId:crypto.randomUUID()}}}),
        reason:'GUARDIAN_LEDGER_SNAPSHOT_CHANGED'},
    ];
    for(const t of cases) {
      let calls=0;
      const result=audit({recentEvents:o=>{
        const p=d.recentEvents(o);
        return ++calls===2?t.change(p):p;
      }},3).capture();
      hold(result);
      assert.equal(result.reason,t.reason);
      assert.equal(result.failureCount,0);
    }
  });
});

test('malformed objects, unexpected attributes and accessors return no source data',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    j.append(stop());j.append(stop());
    const d=diagnostic(dir), base=d.recentEvents({limit:2});
    const poisons=[
      {...base,secret:'PRIVATE_KEY'},
      {...base,activationAllowed:true},
      {...base,entries:[{...base.entries[0],secret:'PRIVATE_KEY'},base.entries[1]]},
      {...base,entries:[{...base.entries[0],eventId:'bogus'},base.entries[1]]},
      {...base,incident:{...base.incident,secret:'PRIVATE_KEY'}},
      Object.defineProperty({...base},'journalEntries',{
        get(){throw new Error('PRIVATE_KEY');},
      }),
      {...base,entries:Object.freeze([Object.defineProperty({},'eventId',{
        get(){throw Error('PRIVATE_KEY');},
      }),base.entries[1]])},
    ];
    for(const poisoned of poisons) {
      const response=audit({recentEvents(){return poisoned;}},2).capture();
      hold(response);
      assert.equal(response.comparison,'NOT_VERIFIED');
      assert.equal(response.reason,'GUARDIAN_LEDGER_PAGE_UNVERIFIED');
      assert.equal(JSON.stringify(response).includes('PRIVATE_KEY'),false);
    }
  });
});

test('out-of-scope configuration and excessive capture time fail closed',async()=>{
  await withTemp(async(dir)=>{
    const j=writer(dir);
    for(let i=0;i<3;i++)j.append(stop());
    const d=diagnostic(dir);
    const options=[
      null,undefined,{},[],{operator:{}},
      {operator:d,pageSize:0,maxCaptureMs:5000},
      {operator:d,pageSize:51,maxCaptureMs:5000},
      {operator:d,pageSize:3,maxCaptureMs:50},
      {operator:d,pageSize:3,maxCaptureMs:30001},
      {operator:d,pageSize:3,maxCaptureMs:5000,secret:'PRIVATE_KEY'},
    ];
    for(const o of options) {
      assert.throws(()=>createGuardianLocalLedgerAudit(o),
        /GUARDIAN_LEDGER_CONFIG_INVALID/);
    }
    const result=audit({recentEvents(o){
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,130);
      return d.recentEvents(o);
    }},1,100).capture();
    hold(result);
    assert.equal(result.reason,'GUARDIAN_LEDGER_BOUNDS_EXCEEDED');
    assert.equal(result.inspectedEntries,0);
  });
});
