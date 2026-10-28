'use strict';
// G34 only generates throwaway synthetic Ed25519 keys in memory.
// No persistent keys, no filesystem mutation, no trust-anchor enrollment.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {
  createGuardianSignedBaselineEquivocationVerifier,
}=require('../merge-gate-install/guardian-candidate/guardian-signed-baseline-equivocation.cjs');

const ANCHOR='synthetic-test-baseline-anchor';
const SCOPE='NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY';
const KIND='GUARDIAN_EXTERNAL_GENERATION_BASELINE_V1';
const PREFIX=Buffer.from('NOHANDS_GUARDIAN_EXTERNAL_BASELINE_V1\n','utf8');
const SIGNED=['schemaVersion','kind','scope','anchorId','sequence',
  'observedAt','journalSha256','ledgerSha256','journalBytes',
  'ledgerBytes','algorithm'];
const sha=(x)=>crypto.createHash('sha256').update(x).digest('hex');
function fixture(){
  const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({format:'pem',type:'spki'});
  const pinnedSpkiSha256=sha(publicKey.export({format:'der',type:'spki'}));
  const fresh=(overrides={})=>{
    const signed={
      schemaVersion:1,kind:KIND,scope:SCOPE,anchorId:ANCHOR,
      sequence:1,observedAt:'2026-10-28T08:00:00.000Z',
      journalSha256:'a'.repeat(64),ledgerSha256:'b'.repeat(64),
      journalBytes:200,ledgerBytes:300,algorithm:'Ed25519',
      ...overrides,
    };
    const fixed={};
    for(const name of SIGNED)fixed[name]=signed[name];
    return JSON.stringify({...signed,signatureBase64:crypto.sign(null,
      Buffer.concat([PREFIX,Buffer.from(JSON.stringify(fixed))]),
      privateKey).toString('base64')});
  };
  const create=(overrides={})=>
    createGuardianSignedBaselineEquivocationVerifier({
      expectedAnchorId:ANCHOR,publicKeyPem,pinnedSpkiSha256,
      ...overrides,
    });
  return {fresh,create,publicKeyPem,pinnedSpkiSha256};
}
function hold(v) {
  assert.equal(v.schemaVersion,1);
  assert.equal(v.kind,'GUARDIAN_SIGNED_BASELINE_EQUIVOCATION_V1');
  assert.equal(v.status,'SOURCE_ONLY_HOLD');
  assert.equal(v.authority,'OWNER_PINNED_PUBLIC_KEY_UNATTESTED');
  assert.equal(v.externalAnchorVerified,false);
  assert.equal(v.historicalCompletenessVerified,false);
  assert.equal(v.custodyVerified,false);
  assert.equal(v.durableAntiRollbackVerified,false);
  assert.equal(v.liveness,'NOT_PROVEN');
  assert.equal(v.manualInterventionRequired,true);
  assert.equal(v.automaticRestartAllowed,false);
  assert.equal(v.activationAllowed,false);
  assert.equal(v.releaseAuthority,'NOT_ISSUED');
  assert.ok(Object.isFrozen(v));
  for(const key of ['rawEnvelope','privateKey','token','actor',
    'trustEnrollment','issueCheck','restart','release','pid']){
    assert.equal(Object.hasOwn(v,key),false);
  }
}
function deny(v, reason){
  hold(v);
  assert.equal(v.reason,reason);
  assert.equal(v.comparison,'NOT_VERIFIED');
  assert.equal(v.locallyVerifiedSignatures,false);
  assert.equal(v.earlierSignedSha256,null);
  assert.equal(v.laterSignedSha256,null);
}
test('module construction is inert and exposes exactly three frozen, nonauthorizing capabilities',()=>{
  const f=fixture(),w=f.create();
  assert.deepEqual(Object.keys(w),['compare','observe','observeBatch']);
  assert.ok(Object.isFrozen(w));
  deny(w.observe('{}'),'GUARDIAN_SIGNED_BASELINE_INPUT_UNVERIFIED');
  assert.equal(w.compare(null,'').comparison,'NOT_VERIFIED');
});
test('same signed sequence, different journal digest is observable conflict, never trusted authority',()=>{
  const f=fixture(),v=f.create();
  const a=f.fresh(),b=f.fresh({journalSha256:'c'.repeat(64)});
  const c=v.compare(a,b);
  hold(c);
  assert.equal(c.reason,'GUARDIAN_SIGNED_BASELINE_EQUIVOCATION_OBSERVED');
  assert.equal(c.comparison,'LOCAL_SIGNED_CONFLICT_ONLY');
  assert.equal(c.locallyVerifiedSignatures,true);
  assert.equal(c.earlierSequence,1);
  assert.equal(c.laterSequence,1);
  assert.notEqual(c.earlierSignedSha256,c.laterSignedSha256);
});
test('same sequence with changed timestamp or source length also conflicts',()=>{
  const f=fixture();
  for(const update of [
    {observedAt:'2026-10-28T08:00:01.000Z'},
    {ledgerSha256:'d'.repeat(64)},{ledgerBytes:301},
  ]){
    const r=f.create().compare(f.fresh(),f.fresh(update));
    hold(r);
    assert.equal(r.comparison,'LOCAL_SIGNED_CONFLICT_ONLY');
  }
});
test('identical signed statement is a replay, not proof of complete history',()=>{
  const f=fixture(),v=f.create(),data=f.fresh();
  const r=v.compare(data,data);
  hold(r);
  assert.equal(r.comparison,'LOCAL_SIGNED_REPLAY_ONLY');
  assert.equal(r.earlierSignedSha256,r.laterSignedSha256);
  assert.equal(r.reason,'GUARDIAN_SIGNED_BASELINE_REPLAY_OBSERVED');
});
test('two correctly signed increasing sequences show order only, never append integrity',()=>{
  const f=fixture(),v=f.create();
  const r=v.compare(f.fresh(),f.fresh({sequence:5}));
  hold(r);
  assert.equal(r.comparison,'LOCAL_SIGNED_ORDER_ONLY');
  assert.equal(r.reason,'GUARDIAN_SIGNED_BASELINE_MONOTONIC_ORDER_OBSERVED');
  assert.equal(r.earlierSequence,1);
  assert.equal(r.laterSequence,5);
  assert.equal(r.historicalCompletenessVerified,false);
});
test('two correctly signed reversed sequences are rollback observations, still HOLD',()=>{
  const f=fixture();
  const r=f.create().compare(f.fresh({sequence:8}),f.fresh());
  hold(r);
  assert.equal(r.reason,'GUARDIAN_SIGNED_BASELINE_ROLLBACK_OBSERVED');
  assert.equal(r.comparison,'LOCAL_SIGNED_ROLLBACK_ONLY');
});
test('first in-memory statement always unanchored; same sequence contradiction latches permanently',()=>{
  const f=fixture(),w=f.create(),a=f.fresh(),b=f.fresh({
    journalSha256:'c'.repeat(64),
  });
  const first=w.observe(a);
  deny(first,'GUARDIAN_SIGNED_BASELINE_FIRST_UNANCHORED_OBSERVATION');
  assert.equal(first.witnessedStatements,1);
  let r=w.observe(b);
  hold(r);
  assert.equal(r.comparison,'LOCAL_SIGNED_CONFLICT_ONLY');
  assert.equal(r.witnessedStatements,1);
  r=w.observe(f.fresh({sequence:2}));
  deny(r,'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED');
  assert.equal(r.witnessedStatements,1);
});
test('duplicate same sequence does not consume capacity or mint second observation',()=>{
  const f=fixture(),w=f.create(),a=f.fresh();
  w.observe(a);
  const replay=w.observe(a);
  hold(replay);
  assert.equal(replay.comparison,'LOCAL_SIGNED_REPLAY_ONLY');
  assert.equal(replay.witnessedStatements,1);
  const forward=w.observe(f.fresh({sequence:2}));
  assert.equal(forward.comparison,'LOCAL_SIGNED_ORDER_ONLY');
  assert.equal(forward.witnessedStatements,2);
});
test('rollback to unseen lower sequence after a higher accepted statement cannot reset progress',()=>{
  const f=fixture(),w=f.create();
  w.observe(f.fresh({sequence:10}));
  const r=w.observe(f.fresh({sequence:8}));
  hold(r);
  assert.equal(r.comparison,'LOCAL_SIGNED_ROLLBACK_ONLY');
  assert.equal(r.witnessedStatements,1);
  const forward=w.observe(f.fresh({sequence:11}));
  assert.equal(forward.comparison,'LOCAL_SIGNED_ORDER_ONLY');
  assert.equal(forward.witnessedStatements,2);
});
test('malformed duplicate-key, noncanonical Base64 and foreign anchor never mutate witness state',()=>{
  const f=fixture(),w=f.create(),good=f.fresh();
  const invalid=[
    good.replace('"sequence":1','"sequence":1,"sequence":2'),
    good.replace('"journalSha256":"','"journalSha256":"a","journalSha256":"'),
    good+'END_PRIVATE_KEY',
    good.replace('"anchorId":"'+ANCHOR+'"',
      '"anchorId":"different-anchor"'),
    good.replace('"algorithm":"Ed25519"',
      '"algorithm":"RSA"'),
    good.replace('"signatureBase64":"','"signatureBase64":"AA'),
    JSON.stringify({...JSON.parse(good),token:'PRIVATE'}),
    '{bad',
    ' '.repeat(8193),
  ];
  for(const input of invalid){
    const r=w.observe(input);
    deny(r,'GUARDIAN_SIGNED_BASELINE_INPUT_UNVERIFIED');
    assert.equal(r.witnessedStatements,0);
    assert.equal(JSON.stringify(r).includes('PRIVATE'),false);
  }
  assert.equal(w.observe(good).witnessedStatements,1);
});
test('invalid objects, buffer, Unicode surrogate, getter/Proxy cannot act as signed input',()=>{
  const f=fixture(),w=f.create();
  const evil=new Proxy({},{
    get(){throw new Error('PRIVATE_TOKEN');},
  });
  for(const value of [undefined,null,{},[],evil,Buffer.from(f.fresh()),
    '\ud800',0,Symbol('token')]){
    const r=w.observe(value);
    deny(r,'GUARDIAN_SIGNED_BASELINE_INPUT_UNVERIFIED');
  }
});
test('signed payload with a modified signature is rejected even if all visible claims remain equal',()=>{
  const f=fixture(),original=JSON.parse(f.fresh());
  const sig=original.signatureBase64;
  original.signatureBase64=(sig[0]==='A'?'B':'A')+sig.slice(1);
  deny(f.create().observe(JSON.stringify(original)),
    'GUARDIAN_SIGNED_BASELINE_INPUT_UNVERIFIED');
});
test('foreign pinned signer key, wrong SPKI fingerprint or dangerous configuration never accepted',()=>{
  const f=fixture(),other=fixture();
  for(const overrides of [
    {publicKeyPem:other.publicKeyPem},
    {pinnedSpkiSha256:'0'.repeat(64)},
    {expectedAnchorId:'Bad Id'},
    {expectedAnchorId:ANCHOR,unexpected:'TOKEN'},
    {publicKeyPem:'-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----'},
  ]){
    assert.throws(()=>f.create(overrides));
  }
  assert.throws(()=>createGuardianSignedBaselineEquivocationVerifier(
    new Proxy({}, {ownKeys(){throw new Error('PRIVATE_TOKEN');}})),
  /GUARDIAN_EQUIVOCATION_CONFIG_INVALID/);
});
test('bounded witness limit fails closed and never evicts old signed conflict evidence',()=>{
  const f=fixture(),w=f.create();
  for(let n=1;n<=64;n++){
    const r=w.observe(f.fresh({sequence:n}));
    hold(r);
    assert.equal(r.witnessedStatements,n);
  }
  deny(w.observe(f.fresh({sequence:65})),
    'GUARDIAN_SIGNED_BASELINE_MEMORY_LIMIT_REACHED');
  deny(w.observe(f.fresh({sequence:1,journalSha256:'c'.repeat(64)})),
    'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED');
});
test('fresh verifier does not inherit memory-only comparison state after instance restart',()=>{
  const f=fixture(),a=f.create(),packet=f.fresh({sequence:8});
  a.observe(packet);
  const b=f.create();
  deny(b.observe(packet),'GUARDIAN_SIGNED_BASELINE_FIRST_UNANCHORED_OBSERVATION');
  assert.equal(b.observe(packet).comparison,'LOCAL_SIGNED_REPLAY_ONLY');
});
