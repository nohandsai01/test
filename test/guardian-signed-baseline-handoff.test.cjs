'use strict';
// G36 cross-instance portable handoff: synthetic in-memory signing only.
// Verifier never receives a private key or grants any external authority.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {
  createGuardianSignedBaselineHandoff,
}=require('../merge-gate-install/guardian-candidate/guardian-signed-baseline-handoff.cjs');

const ID='synthetic-handoff-anchor';
const SCOPE='NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY';
const PREFIX=Buffer.from('NOHANDS_GUARDIAN_EXTERNAL_BASELINE_V1\n');
const DOMAIN=Buffer.from('NOHANDS_GUARDIAN_SIGNED_BASELINE_HANDOFF_V1\n');
const SIGNED_FIELDS=['schemaVersion','kind','scope','anchorId',
  'sequence','observedAt','journalSha256','ledgerSha256','journalBytes',
  'ledgerBytes','algorithm'];
const OUTER_FIELDS=['schemaVersion','kind','scope','anchorId',
  'pinnedSpkiSha256','statementCount','firstSequence','lastSequence',
  'statements'];
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function setup(){
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({format:'pem',type:'spki'});
  const pinnedSpkiSha256=sha(publicKey.export({format:'der',type:'spki'}));
  const config={expectedAnchorId:ID,publicKeyPem,pinnedSpkiSha256};
  const create=extra=>createGuardianSignedBaselineHandoff({...config,...extra});
  const signed=(sequence,delta={})=>{
    const fields={
      schemaVersion:1,kind:'GUARDIAN_EXTERNAL_GENERATION_BASELINE_V1',
      scope:SCOPE,anchorId:ID,sequence,
      observedAt:'2026-10-28T07:15:00.000Z',
      journalSha256:'a'.repeat(64),ledgerSha256:'b'.repeat(64),
      journalBytes:300,ledgerBytes:400,algorithm:'Ed25519',...delta,
    };
    const unsigned={};
    for(const field of SIGNED_FIELDS)unsigned[field]=fields[field];
    const signatureBase64=crypto.sign(null,Buffer.concat([PREFIX,
      Buffer.from(JSON.stringify(unsigned))]),privateKey).toString('base64');
    return JSON.stringify({...fields,signatureBase64});
  };
  return {create,signed,config};
}
function redacted(result){
  assert.equal(result.schemaVersion,1);
  assert.equal(result.kind,'GUARDIAN_SIGNED_BASELINE_HANDOFF_RESULT_V1');
  assert.equal(result.status,'SOURCE_ONLY_HOLD');
  assert.equal(result.authority,'OWNER_PINNED_PUBLIC_KEY_UNATTESTED');
  assert.equal(result.externalAnchorVerified,false);
  assert.equal(result.durableCustodyVerified,false);
  assert.equal(result.historicalCompletenessVerified,false);
  assert.equal(result.durableAntiRollbackVerified,false);
  assert.equal(result.custodyVerified,false);
  assert.equal(result.liveness,'NOT_PROVEN');
  assert.equal(result.manualInterventionRequired,true);
  assert.equal(result.activationAllowed,false);
  assert.equal(result.automaticRestartAllowed,false);
  assert.equal(result.releaseAuthority,'NOT_ISSUED');
  assert.ok(Object.isFrozen(result));
  for(const key of ['privateKey','signedStatements','rawHandoff',
    'token','issueCheck','clearHold','restart','merge','deploy']){
    assert.equal(Object.hasOwn(result,key),false);
  }
}
function rejected(result,reason){
  redacted(result);
  assert.equal(result.reason,reason);
  assert.equal(result.comparison,'NOT_VERIFIED');
  assert.equal(result.firstSequence,null);
  assert.equal(result.lastSequence,null);
  assert.equal(result.observedStatements,0);
  assert.equal(result.handoffSha256,null);
  assert.equal(result.innerSignaturesLocallyVerified,false);
}
function success(result,first,last,count){
  redacted(result);
  assert.equal(result.reason,'GUARDIAN_HANDOFF_LOCAL_SIGNED_BATCH_VERIFIED');
  assert.equal(result.comparison,'LOCAL_SIGNED_HANDOFF_ONLY');
  assert.equal(result.firstSequence,first);
  assert.equal(result.lastSequence,last);
  assert.equal(result.observedStatements,count);
  assert.match(result.handoffSha256,/^[0-9a-f]{64}$/);
  assert.equal(result.innerSignaturesLocallyVerified,true);
}
function transport(packet){
  const unsigned={};
  for(const k of OUTER_FIELDS)unsigned[k]=packet[k];
  return {...unsigned,handoffSha256:sha(Buffer.concat([DOMAIN,
    Buffer.from(JSON.stringify(unsigned),'utf8')]))};
}
function craft(raw,modify,recalculate=false){
  const packet=JSON.parse(raw);
  modify(packet);
  if(recalculate)return JSON.stringify(transport(packet));
  return JSON.stringify(packet);
}
test('inert constructor and API have no signing, storage or acceptance capabilities',()=>{
  const f=setup(),provider=f.create();
  assert.ok(Object.isFrozen(provider));
  assert.deepEqual(Object.keys(provider),['prepareHandoff','verifyHandoff']);
  assert.equal(provider.prepareHandoff([]),null);
  rejected(provider.verifyHandoff('{}'),'GUARDIAN_HANDOFF_CONTRACT_INVALID');
});
test('two independent verifier instances exchange portable signed evidence and remain HOLD',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const statements=[f.signed(5),f.signed(7),f.signed(12)];
  const packet=sender.prepareHandoff(statements);
  assert.equal(packet.schemaVersion,1);
  assert.equal(packet.status,'SOURCE_ONLY_HOLD');
  assert.equal(packet.externalAnchorVerified,false);
  assert.equal(packet.durableCustodyVerified,false);
  assert.equal(packet.locallyVerifiedStatements,3);
  assert.ok(Object.isFrozen(packet));
  const raw=JSON.parse(packet.handoffJson);
  assert.deepEqual(raw.statements,statements);
  assert.equal(raw.handoffSha256,packet.handoffSha256);
  success(receiver.verifyHandoff(packet.handoffJson),5,12,3);
  // Sender preparation did not mutate its RECEIVING witness.
  success(sender.verifyHandoff(packet.handoffJson),5,12,3);
});
test('later handoff batch extends same receiver witness but does not prove contiguous history',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const early=sender.prepareHandoff([f.signed(1),f.signed(3)]);
  const later=sender.prepareHandoff([f.signed(20),f.signed(90)]);
  success(receiver.verifyHandoff(early.handoffJson),1,3,2);
  const result=receiver.verifyHandoff(later.handoffJson);
  success(result,20,90,4);
  assert.equal(result.historicalCompletenessVerified,false);
});
test('same handoff replay cannot promote or accept another observation',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const a=sender.prepareHandoff([f.signed(5)]);
  success(receiver.verifyHandoff(a.handoffJson),5,5,1);
  rejected(receiver.verifyHandoff(a.handoffJson),
    'GUARDIAN_HANDOFF_SIGNED_REPLAY_OBSERVED');
  success(receiver.verifyHandoff(sender.prepareHandoff([f.signed(6)])
    .handoffJson),6,6,2);
});
test('outer SHA mismatch rejects before receiver accepts any signed inner item',()=>{
  const f=setup(),a=f.create(),b=f.create();
  const proper=a.prepareHandoff([f.signed(10),f.signed(12)]);
  const changed=craft(proper.handoffJson,p=>{p.firstSequence=11;});
  rejected(b.verifyHandoff(changed),
    'GUARDIAN_HANDOFF_TRANSPORT_DIGEST_MISMATCH');
  success(b.verifyHandoff(proper.handoffJson),10,12,2);
});
test('recomputed outer SHA with forged sequence claim rejects BEFORE altering witness',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const good=sender.prepareHandoff([f.signed(20),f.signed(23)]);
  const forged=craft(good.handoffJson,p=>{p.firstSequence=19;},true);
  rejected(receiver.verifyHandoff(forged),
    'GUARDIAN_HANDOFF_SEQUENCE_CLAIM_MISMATCH');
  success(receiver.verifyHandoff(good.handoffJson),20,23,2);
});
test('changed anchor, pin or scope with recomputed transport digest remains rejected',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const base=sender.prepareHandoff([f.signed(5)]);
  for(const edit of [
    p=>{p.anchorId='different-anchor';},
    p=>{p.pinnedSpkiSha256='0'.repeat(64);},
    p=>{p.scope='PRODUCTION_RELEASE';},
  ]){
    rejected(receiver.verifyHandoff(craft(base.handoffJson,edit,true)),
      'GUARDIAN_HANDOFF_CONTRACT_INVALID');
  }
  success(receiver.verifyHandoff(base.handoffJson),5,5,1);
});
test('malformed or duplicate-key JSON is rejected with no partial source adoption',()=>{
  const f=setup(),a=f.create(),b=f.create();
  const good=a.prepareHandoff([f.signed(1)]);
  for(const bad of [
    '{bad',
    good.handoffJson+' trailing',
    good.handoffJson.replace('"statementCount":1',
      '"statementCount":1,"statementCount":2'),
    good.handoffJson.replace('"handoffSha256":"',
      '"handoffSha256":"x","handoffSha256":"'),
    JSON.stringify({...JSON.parse(good.handoffJson),secret:'PRIVATE'}),
  ]){
    const out=b.verifyHandoff(bad);
    redacted(out);
    assert.equal(out.comparison,'NOT_VERIFIED');
    assert.ok(!JSON.stringify(out).includes('PRIVATE'));
  }
  success(b.verifyHandoff(good.handoffJson),1,1,1);
});
test('invalid tail inner signature with recalculated transport digest cannot accept valid prefix',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const good=sender.prepareHandoff([f.signed(2),f.signed(3)]);
  const forged=craft(good.handoffJson,p=>{
    const bad=JSON.parse(p.statements[1]);
    bad.journalSha256='0'.repeat(64); // signature intentionally stale
    p.statements[1]=JSON.stringify(bad);
  },true);
  rejected(receiver.verifyHandoff(forged),
    'GUARDIAN_HANDOFF_INNER_SIGNATURES_UNVERIFIED');
  success(receiver.verifyHandoff(good.handoffJson),2,3,2);
});
test('contradictory validly signed new batch against observed sequence permanently latches receiver',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const original=sender.prepareHandoff([f.signed(8)]);
  success(receiver.verifyHandoff(original.handoffJson),8,8,1);
  const conflicting=sender.prepareHandoff([
    f.signed(8,{journalSha256:'c'.repeat(64)}),
  ]);
  rejected(receiver.verifyHandoff(conflicting.handoffJson),
    'GUARDIAN_HANDOFF_SIGNED_EQUIVOCATION_OBSERVED');
  const newer=sender.prepareHandoff([f.signed(9)]);
  rejected(receiver.verifyHandoff(newer.handoffJson),
    'GUARDIAN_HANDOFF_WITNESS_LATCHED');
});
test('same batch conflicting sequence cannot be prepared or accepted',()=>{
  const f=setup(),sender=f.create();
  assert.equal(sender.prepareHandoff([
    f.signed(3),f.signed(3,{ledgerSha256:'c'.repeat(64)}),
  ]),null);
});
test('descending sequences and replayed transport are NOT signed continuity',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  assert.equal(sender.prepareHandoff([f.signed(4),f.signed(2)]),null);
  const newer=sender.prepareHandoff([f.signed(100)]);
  const older=sender.prepareHandoff([f.signed(40)]);
  success(receiver.verifyHandoff(newer.handoffJson),100,100,1);
  rejected(receiver.verifyHandoff(older.handoffJson),
    'GUARDIAN_HANDOFF_SIGNED_ROLLBACK_OBSERVED');
});
test('array accessor, sparse, symbol or proxy cannot influence send side',()=>{
  const f=setup(),sender=f.create();
  let reads=0;
  const acc=[f.signed(1)];
  Object.defineProperty(acc,1,{enumerable:true,
    get(){reads++;return f.signed(2);}});
  const sparse=[f.signed(1),,f.signed(3)];
  const symbol=[f.signed(1)];
  symbol[Symbol('secret')]='PRIVATE';
  const proxy=new Proxy([f.signed(1)],{
    ownKeys(){throw new Error('PRIVATE');},
  });
  for(const v of [acc,sparse,symbol,proxy,
    [f.signed(1),{},f.signed(3)],[],new Array(2),{},
    Array.from({length:17},(_,i)=>f.signed(i+1))]){
    assert.equal(sender.prepareHandoff(v),null);
  }
  assert.equal(reads,0);
  assert.ok(sender.prepareHandoff([f.signed(1)]));
});
test('invalid receiving input types or oversized text cannot modify a local witness',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  for(const v of [undefined,null,{},[],Buffer.alloc(150001),0,
    Symbol('private'),'\ud800',' '.repeat(150001)]){
    rejected(receiver.verifyHandoff(v),'GUARDIAN_HANDOFF_TRANSPORT_INVALID');
  }
  const valid=sender.prepareHandoff([f.signed(7)]);
  success(receiver.verifyHandoff(valid.handoffJson),7,7,1);
});
test('new receiver process cannot inherit memory-only antirollback, remains unanchored',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  const old=sender.prepareHandoff([f.signed(42)]);
  success(receiver.verifyHandoff(old.handoffJson),42,42,1);
  const fresh=f.create();
  const again=fresh.verifyHandoff(old.handoffJson);
  success(again,42,42,1);
  assert.equal(again.durableAntiRollbackVerified,false);
  assert.equal(again.externalAnchorVerified,false);
});
test('bounded cumulative witness refusing >64 signed statements does not accept partial handoff',()=>{
  const f=setup(),sender=f.create(),receiver=f.create();
  for(let n=0;n<4;n++){
    const list=Array.from({length:16},(_,i)=>f.signed(n*16+i+1));
    success(receiver.verifyHandoff(sender.prepareHandoff(list).handoffJson),
      n*16+1,n*16+16,(n+1)*16);
  }
  const over=sender.prepareHandoff([f.signed(65)]);
  rejected(receiver.verifyHandoff(over.handoffJson),
    'GUARDIAN_HANDOFF_WITNESS_LATCHED');
  rejected(receiver.verifyHandoff(sender.prepareHandoff([f.signed(66)])
    .handoffJson),'GUARDIAN_HANDOFF_WITNESS_LATCHED');
});
