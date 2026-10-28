'use strict';
// G35: verify all signed claims before any in-memory witness commit.
// Temporary Ed25519 signer exists in TEST FIXTURE ONLY.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {createGuardianSignedBaselineEquivocationVerifier}=require(
  '../merge-gate-install/guardian-candidate/guardian-signed-baseline-equivocation.cjs');
const fields=['schemaVersion','kind','scope','anchorId','sequence',
  'observedAt','journalSha256','ledgerSha256','journalBytes',
  'ledgerBytes','algorithm'];
const PREFIX=Buffer.from('NOHANDS_GUARDIAN_EXTERNAL_BASELINE_V1\n');
const ID='synthetic-g35-only-anchor';
function fixture() {
  const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
  const spki=publicKey.export({format:'der',type:'spki'});
  const w=createGuardianSignedBaselineEquivocationVerifier({
    expectedAnchorId:ID,publicKeyPem:publicKey.export({format:'pem',type:'spki'}),
    pinnedSpkiSha256:crypto.createHash('sha256').update(spki).digest('hex'),
  });
  function make(seq=1,delta={}){
    const body={
      schemaVersion:1,kind:'GUARDIAN_EXTERNAL_GENERATION_BASELINE_V1',
      scope:'NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY',
      anchorId:ID,sequence:seq,observedAt:'2026-10-28T09:00:00.000Z',
      journalSha256:'a'.repeat(64),ledgerSha256:'b'.repeat(64),
      journalBytes:120,ledgerBytes:200,algorithm:'Ed25519',
      ...delta,
    };
    const payload={};
    for(const field of fields)payload[field]=body[field];
    const sig=crypto.sign(null,Buffer.concat([PREFIX,
      Buffer.from(JSON.stringify(payload))]),privateKey).toString('base64');
    return JSON.stringify({...body,signatureBase64:sig});
  }
  return {w,make};
}
function hold(r){
  assert.equal(r.kind,'GUARDIAN_SIGNED_BASELINE_BATCH_V1');
  assert.equal(r.status,'SOURCE_ONLY_HOLD');
  assert.equal(r.authority,'OWNER_PINNED_PUBLIC_KEY_UNATTESTED');
  assert.equal(r.externalAnchorVerified,false);
  assert.equal(r.historicalCompletenessVerified,false);
  assert.equal(r.custodyVerified,false);
  assert.equal(r.durableAntiRollbackVerified,false);
  assert.equal(r.liveness,'NOT_PROVEN');
  assert.equal(r.manualInterventionRequired,true);
  assert.equal(r.activationAllowed,false);
  assert.equal(r.automaticRestartAllowed,false);
  assert.equal(r.releaseAuthority,'NOT_ISSUED');
  assert.ok(Object.isFrozen(r));
  for(const key of ['rawInput','privateKey','events','password',
    'accept','clearHold','sign','publishCheck','restart']){
    assert.equal(Object.hasOwn(r,key),false);
  }
}
function denied(r,reason,total=0){
  hold(r);
  assert.equal(r.reason,reason);
  assert.equal(r.comparison,'NOT_VERIFIED');
  assert.equal(r.addedStatements,0);
  assert.equal(r.observedStatements,total);
  assert.equal(r.firstSequence,null);
  assert.equal(r.lastSequence,null);
  assert.equal(r.locallyVerifiedSignatures,false);
}
test('inert API exposes bounded all-or-nothing observeBatch without write capabilities',()=>{
  const {w}=fixture();
  assert.ok(Object.isFrozen(w));
  assert.deepEqual(Object.keys(w),['compare','observe','observeBatch']);
  denied(w.observeBatch([]),'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID');
});
test('first valid batch of three signatures is unanchored local order, not external authority',()=>{
  const {w,make}=fixture();
  const r=w.observeBatch([make(3),make(5),make(7)]);
  hold(r);
  assert.equal(r.comparison,'LOCAL_SIGNED_BATCH_ORDER_ONLY');
  assert.equal(r.reason,
    'GUARDIAN_SIGNED_BASELINE_BATCH_FIRST_UNANCHORED_OBSERVATION');
  assert.equal(r.observedStatements,3);
  assert.equal(r.addedStatements,3);
  assert.equal(r.firstSequence,3);
  assert.equal(r.lastSequence,7);
  assert.equal(r.locallyVerifiedSignatures,true);
  assert.equal(w.observe(make(7)).comparison,'LOCAL_SIGNED_REPLAY_ONLY');
});
test('second complete batch appends same witness and never claims contiguous sequences',()=>{
  const {w,make}=fixture();
  w.observeBatch([make(1),make(3)]);
  const r=w.observeBatch([make(40),make(100)]);
  hold(r);
  assert.equal(r.comparison,'LOCAL_SIGNED_BATCH_ORDER_ONLY');
  assert.equal(r.reason,'GUARDIAN_SIGNED_BASELINE_BATCH_LOCAL_ORDER_OBSERVED');
  assert.equal(r.observedStatements,4);
  assert.equal(r.addedStatements,2);
  assert.equal(r.firstSequence,40);
  assert.equal(r.lastSequence,100);
  assert.equal(r.historicalCompletenessVerified,false);
});
test('malformed last member must NOT commit the earlier valid signed batch prefix',()=>{
  const {w,make}=fixture();
  w.observe(make(1));
  const r=w.observeBatch([make(2),make(3),'{"bad":"tail"}']);
  denied(r,'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID',1);
  assert.equal(w.observe(make(2)).comparison,'LOCAL_SIGNED_ORDER_ONLY');
  assert.equal(w.observe(make(3)).comparison,'LOCAL_SIGNED_ORDER_ONLY');
});
test('wrong-key signature late in batch must reject whole batch without memory mutation',()=>{
  const first=fixture(),other=fixture();
  const r=first.w.observeBatch([first.make(1),first.make(2),other.make(3)]);
  denied(r,'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID');
  assert.equal(first.w.observe(first.make(1)).witnessedStatements,1);
});
test('same sequence conflicting signed contents within one batch latches but commits nothing',()=>{
  const {w,make}=fixture();
  const a=make(9),different=make(9,{journalSha256:'f'.repeat(64)});
  const r=w.observeBatch([a,different]);
  denied(r,'GUARDIAN_SIGNED_BASELINE_BATCH_EQUIVOCATION_OBSERVED');
  denied(w.observeBatch([make(10)]),
    'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED');
  denied(w.observeBatch([a]),
    'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED');
});
test('conflict with previously witnessed source latches without committing new batch prefix',()=>{
  const {w,make}=fixture();
  w.observe(make(1));
  const r=w.observeBatch([make(2),make(1,{ledgerSha256:'c'.repeat(64)})]);
  denied(r,'GUARDIAN_SIGNED_BASELINE_BATCH_EQUIVOCATION_OBSERVED',1);
  denied(w.observeBatch([make(3)]),
    'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED',1);
});
test('replay or duplicate sequence inside same batch rejects without creating a second observation',()=>{
  const {w,make}=fixture();
  const a=make(5);
  denied(w.observeBatch([a,a]),
    'GUARDIAN_SIGNED_BASELINE_BATCH_REPLAY_OBSERVED');
  const after=w.observeBatch([a,make(6)]);
  assert.equal(after.addedStatements,2);
  assert.equal(after.observedStatements,2);
});
test('batch descending/newer then older is rollback, no partial accepted',()=>{
  const {w,make}=fixture();
  denied(w.observeBatch([make(15),make(14)]),
    'GUARDIAN_SIGNED_BASELINE_BATCH_ROLLBACK_OBSERVED');
  assert.equal(w.observe(make(14)).witnessedStatements,1);
});
test('batch appended below prior max is rollback, unaffected first local generation',()=>{
  const {w,make}=fixture();
  w.observe(make(12));
  denied(w.observeBatch([make(13),make(11)]),
    'GUARDIAN_SIGNED_BASELINE_BATCH_ROLLBACK_OBSERVED',1);
  assert.equal(w.observe(make(13)).witnessedStatements,2);
});
test('previously accepted exact duplicate causes batch replay without partial update',()=>{
  const {w,make}=fixture();
  w.observe(make(1));
  denied(w.observeBatch([make(1),make(2)]),
    'GUARDIAN_SIGNED_BASELINE_BATCH_REPLAY_OBSERVED',1);
  assert.equal(w.observe(make(2)).witnessedStatements,2);
});
test('invalid getter/proxy/symbol/sparse/hole array is fail-closed without invoking element getter',()=>{
  const {w,make}=fixture();
  let invoked=0;
  const dynamic=[make(1)];
  Object.defineProperty(dynamic,1,{get(){invoked++;return make(2);},
    enumerable:true,configurable:true});
  const symbol=[make(1)];
  symbol[Symbol('secret')]=make(2);
  const sparse=[make(1),,make(3)];
  const proxy=new Proxy([make(1)],{
    ownKeys(){throw new Error('PRIVATE_TOKEN');},
  });
  for(const input of [dynamic,symbol,sparse,proxy,{0:make(1),length:1},
    new Array(1)]){
    const r=w.observeBatch(input);
    denied(r,'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID');
    assert.ok(!JSON.stringify(r).includes('PRIVATE_TOKEN'));
  }
  assert.equal(invoked,0);
  assert.equal(w.observe(make(1)).witnessedStatements,1);
});
test('batch upper bound 16 enforced, no partial results or allocation of excess signatures',()=>{
  const {w,make}=fixture();
  denied(w.observeBatch(Array.from({length:17},(_,i)=>make(i+1))),
    'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID');
  const accepted=w.observeBatch(Array.from({length:16},(_,i)=>make(i+1)));
  hold(accepted);
  assert.equal(accepted.addedStatements,16);
  assert.equal(accepted.observedStatements,16);
});
test('capacity crossed by final batch member is sticky HOLD without partial write',()=>{
  const {w,make}=fixture();
  for(let n=1;n<=60;n++)w.observe(make(n));
  const r=w.observeBatch(Array.from({length:8},(_,i)=>make(61+i)));
  denied(r,'GUARDIAN_SIGNED_BASELINE_MEMORY_LIMIT_REACHED',60);
  denied(w.observeBatch([make(61)]),
    'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED',60);
});
test('sequence and digest observations never outlive new verifier instance',()=>{
  const f=fixture();
  f.w.observeBatch([f.make(10),f.make(11)]);
  const second=fixture();
  const r=second.w.observeBatch([second.make(10)]);
  assert.equal(r.reason,
    'GUARDIAN_SIGNED_BASELINE_BATCH_FIRST_UNANCHORED_OBSERVATION');
  assert.equal(r.externalAnchorVerified,false);
  assert.equal(r.durableAntiRollbackVerified,false);
});
