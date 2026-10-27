'use strict';
// Isolated Operator-only fault summary; no production App/D1/Check.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createGuardianOfflineIncidentBrief } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-offline-incident-brief.cjs');
const { createGuardianLocalOperatorSession } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-operator-session.cjs');
const { createGuardianLocalReceiptJournal } = require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const worker = path.join(__dirname, 'guardian-protected-worker-child.cjs');
const sha = 'a'.repeat(64);
const good = () => ({
  state:'STOPPED',errorCode:null,hostStopped:true,activationAllowed:false,
  releaseAuthority:'NOT_ISSUED',automaticRestartAllowed:false,
});
const bad = () => ({
  state:'FAILED',errorCode:'GUARDIAN_CHILD_EXIT_UNVERIFIED',hostStopped:false,
  activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  automaticRestartAllowed:false,
});
async function withTemp(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-g27a-'));
  try { return await callback(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
function makeSession(directory) {
  return createGuardianLocalOperatorSession({
    cwd: path.dirname(worker), entrypoint: worker,
    directory, fileName: 'guardian-offline-audit.jsonl',
    startupTimeoutMs: 4000, shutdownTimeoutMs: 900,
  });
}
function journal(directory) {
  return createGuardianLocalReceiptJournal({
    directory, fileName: 'guardian-offline-audit.jsonl',
  });
}
function assertHold(r) {
  assert.equal(r.status, 'SOURCE_ONLY_HOLD');
  assert.equal(r.authority, 'LOCAL_UNAUTHENTICATED_OBSERVATION');
  assert.equal(r.liveness, 'NOT_PROVEN');
  assert.equal(r.manualInterventionRequired, true);
  assert.equal(r.automaticRestartAllowed, false);
  assert.equal(r.activationAllowed, false);
  assert.equal(r.releaseAuthority, 'NOT_ISSUED');
  assert.match(r.briefSha256, /^[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(r), true);
  assert.equal(Object.isFrozen(r.events), true);
  for (const e of r.events) {
    assert.ok(Object.isFrozen(e));
    assert.deepEqual(Object.keys(e).sort(),
      ['eventId','timestamp','state','errorCode'].sort());
  }
  for (const name of ['pid','token','privateKey','rawJournal','restart',
    'postCheck','clearHold']) assert.equal(Object.hasOwn(r,name),false);
}

function assessment(opts={}) {
  return Object.freeze({
    schemaVersion:1,
    kind:'GUARDIAN_LOCAL_RUNTIME_ASSESSMENT_V1',
    authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status:'SOURCE_ONLY_HOLD', priority:'P2',
    classification:'PROCESS_STATE_UNPROVEN',
    nextAction:'OWNER_RECONCILE_LIFECYCLE',
    processState:'RUNNING',
    triageReason:'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE',
    healthFreshness:'UNVERIFIED',
    healthReason:'GUARDIAN_HEALTH_NO_VALID_SAMPLE',
    healthSampleAgeMs:null, healthMaxAgeMs:1000,
    journalSha256:sha,journalEntries:2,
    historicalFailureCount:1,
    liveness:'NOT_PROVEN',manualInterventionRequired:true,
    automaticRestartAllowed:false,activationAllowed:false,
    releaseAuthority:'NOT_ISSUED', ...opts,
  });
}
function row(state='STOPPED', code=null) {
  return Object.freeze({
    eventId: crypto.randomUUID(), timestamp:'2026-10-27T01:00:00.000Z',
    state,errorCode:code,
  });
}
function page(opts={}) {
  const entries=Object.freeze([
    row('STOPPED'), row('FAILED','GUARDIAN_CHILD_EXIT_UNVERIFIED')]);
  return Object.freeze({
    schemaVersion:1, status:'SOURCE_ONLY_HOLD',
    reason:'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED',
    processState:'RUNNING',
    journalSha256:sha,journalEntries:2,
    liveness:'NOT_PROVEN',automaticRestartAllowed:false,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    entries, nextCursor:null,
    incident:Object.freeze({failureCount:1,firstFailure:entries[1],
      latestFailure:entries[1],manualInterventionRequired:true}),
    ...opts,
  });
}
function harness(a=()=>assessment(),p=()=>page()) {
  const count={a:0,p:0};
  const operator={
    assessRuntime(){count.a++;return a();},
    recentEvents(opts){count.p++;assert.deepEqual(opts,{limit:5});return p();},
    start(){throw new Error('SHOULD_NOT_START');},
    stop(){throw new Error('SHOULD_NOT_STOP');},
    probeRuntime(){throw new Error('SHOULD_NOT_PROBE');},
  };
  return {count, brief:createGuardianOfflineIncidentBrief({operator})};
}
test('import and construction are inert; one redacted snapshot is deterministic',()=>{
  const a=assessment(), p=page(), {count,brief}=harness(()=>a,()=>p);
  assert.deepEqual(count,{a:0,p:0});
  assert.deepEqual(Object.keys(brief),['capture']);
  const first=brief.capture(), second=brief.capture();
  assertHold(first);assertHold(second);
  assert.equal(first.classification,'LOCAL_BRIEF_CONSISTENT');
  assert.equal(first.priority,'P2');
  assert.equal(first.journalEntries,2);
  assert.equal(first.historicalFailureCount,1);
  assert.equal(first.events.length,2);
  assert.equal(first.briefSha256,second.briefSha256);
  assert.deepEqual(count,{a:4,p:2});
});
test('modified journal digest, count, classification or fault count between bracketed reads is P0',()=>{
  for(const change of [
    {journalSha256:'b'.repeat(64)}, {journalEntries:3},
    {historicalFailureCount:0}, {classification:'EVIDENCE_UNVERIFIED'},
    {processState:'STOPPED'}, {healthFreshness:'EXPIRED'},
  ]){
    let n=0;
    const h=harness(()=>++n===1?assessment():assessment(change));
    const r=h.brief.capture();assertHold(r);
    assert.equal(r.classification,'LOCAL_BRIEF_EVIDENCE_CHANGED');
    assert.equal(r.priority,'P0');assert.equal(r.journalSha256,null);
    assert.equal(r.events.length,0);
  }
});
test('event pagination from another journal digest is rejected',()=>{
  for(const change of [
    {journalSha256:'b'.repeat(64)}, {journalEntries:3},
    {processState:'STOPPED'},
    {activationAllowed:true},
    {entries:[]},
  ]){
    const h=harness(()=>assessment(),()=>page(change));
    const r=h.brief.capture();assertHold(r);
    assert.equal(r.classification,'LOCAL_BRIEF_EVIDENCE_CHANGED');
    assert.equal(r.events.length,0);
  }
});
test('forged operator authority and dynamic getters never appear in output',()=>{
  for(const poisoned of [
    ()=>assessment({releaseAuthority:'ISSUED'}),
    ()=>assessment({activationAllowed:true}),
    ()=>Object.defineProperty({},'schemaVersion',{
      get(){throw new Error('PRIVATE_KEY_PROTECTED');},
    }),
    ()=>({...assessment(), secret:'SENSITIVE_TOKEN'}),
  ]){
    const r=harness(poisoned).brief.capture();
    assertHold(r);assert.equal(r.priority,'P0');
    assert.equal(r.classification,'LOCAL_BRIEF_SOURCE_UNVERIFIED');
    assert.equal(r.journalEntries,0);
    assert.equal(JSON.stringify(r).includes('PRIVATE_KEY'),false);
    assert.equal(JSON.stringify(r).includes('SENSITIVE_TOKEN'),false);
  }
});
test('hostile event metadata, duplicate events and unexpected accessors fail closed',()=>{
  const duplicate=row('STOPPED');
  for(const events of [
    Object.freeze([duplicate,duplicate]),
    Object.freeze([Object.freeze({ ...duplicate,token:'PRIVATE_KEY' })]),
    Object.freeze([Object.defineProperty({},'eventId',{
      get(){throw new Error('SENSITIVE');},
    })]),
    Object.freeze([row('RUNNING')]),
  ]){
    const result=harness(()=>assessment(),()=>page({entries})).brief.capture();
    assertHold(result);assert.equal(result.priority,'P0');
    assert.equal(result.events.length,0);
    assert.equal(JSON.stringify(result).includes('PRIVATE_KEY'),false);
  }
});
test('missing journal, P0 assessment and failed operator query stay P0 with no reads beyond necessity',()=>{
  const invalid=assessment({priority:'P0',
    classification:'LOCAL_OBSERVATION_UNVERIFIED'});
  const h=harness(()=>invalid,()=>{throw Error('SHOULD_NOT_QUERY');});
  const r=h.brief.capture();assertHold(r);
  assert.equal(r.classification,'LOCAL_BRIEF_SOURCE_UNVERIFIED');
  assert.deepEqual(h.count,{a:1,p:0});
  const absent=harness(()=>assessment({journalSha256:null}),()=>page())
    .brief.capture();
  assert.equal(absent.priority,'P0');
  const failed=harness(()=>assessment(),()=>{throw Error('SECRET');})
    .brief.capture();
  assert.equal(failed.classification,'LOCAL_BRIEF_READ_FAILED');
  assertHold(failed);
});
test('slow passive page read cannot be used to mint a consistent report',()=>{
  const h=harness(()=>assessment(),()=>{
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,65);
    return page();
  });
  const custom=createGuardianOfflineIncidentBrief({
    operator:{assessRuntime:()=>assessment(),recentEvents:()=>page()},
    maxCaptureMs:50,
  });
  assert.equal(custom.capture().classification,'LOCAL_BRIEF_CONSISTENT');
  const slow=createGuardianOfflineIncidentBrief({
    operator:{
      assessRuntime:()=>assessment(),
      recentEvents:()=>{
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,65);
        return page();
      },
    },maxCaptureMs:50});
  assert.equal(slow.capture().classification,'LOCAL_BRIEF_EVIDENCE_CHANGED');
});
test('invalid options are rejected without reading operator capabilities',()=>{
  const {brief}=harness();
  assert.ok(brief);
  for(const opts of [null,{}, {operator:{}},{operator:{assessRuntime(){}}},
    {operator:{assessRuntime(){},recentEvents(){}},limit:0},
    {operator:{assessRuntime(){},recentEvents(){}},limit:11},
    {operator:{assessRuntime(){},recentEvents(){}},maxCaptureMs:0},
    {operator:{assessRuntime(){},recentEvents(){}},unsafe:true}]){
    assert.throws(()=>createGuardianOfflineIncidentBrief(opts));
  }
});
test('real local owner-only journal and operator session produce redacted offline brief',async()=>{
  await withTemp(async(directory)=>{
    const store=journal(directory);
    store.append(good());store.append(bad());store.append(good());
    const session=makeSession(directory);
    const brief=createGuardianOfflineIncidentBrief({
      operator:session.operator,limit:3});
    const r=brief.capture();
    assertHold(r);
    assert.equal(r.classification,'LOCAL_BRIEF_CONSISTENT');
    assert.equal(r.priority,'P1');
    assert.equal(r.historicalFailureCount,1);
    assert.equal(r.events.length,3);
    assert.equal(r.journalEntries,3);
    assert.ok(r.events.some(e=>e.state==='FAILED'));
    assert.equal(fs.readdirSync(directory).length,1);
  });
});
