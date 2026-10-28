/**
 * G36 — portable, offline, nonauthorizing signed-baseline handoff.
 *
 * The outer SHA-256 checks transport integrity, NOT authenticity. Every
 * inner G33 Ed25519 envelope is reverified using an owner-supplied pinned
 * SPKI public key, then fed to G35's all-or-nothing volatile witness.
 *
 * No file/network access, key creation, signer API, durable history store,
 * trusted-anchor registration, Check publication or automatic HOLD release.
 */
'use strict';
const crypto=require('node:crypto');
const {parseUniqueKeySourceLock}=require('../candidate/verify-source-lock.cjs');
const {createGuardianSignedBaselineEquivocationVerifier}=
  require('./guardian-signed-baseline-equivocation.cjs');

const KEY_FIELDS=Object.freeze([
  'expectedAnchorId','publicKeyPem','pinnedSpkiSha256',
]);
const PACKET_FIELDS=Object.freeze([
  'schemaVersion','kind','scope','anchorId','pinnedSpkiSha256',
  'statementCount','firstSequence','lastSequence','statements',
]);
const ALL_FIELDS=Object.freeze([...PACKET_FIELDS,'handoffSha256']);
const KIND='GUARDIAN_SIGNED_BASELINE_HANDOFF_V1';
const SCOPE='NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY';
const DOMAIN=Buffer.from('NOHANDS_GUARDIAN_SIGNED_BASELINE_HANDOFF_V1\n');
const SHA=/^[0-9a-f]{64}$/;
const ANCHOR=/^[a-z][a-z0-9-]{3,63}$/;
const MAX_MEMBERS=16;
const MAX_SIGNED_BYTES=8192;
const MAX_TRANSPORT_BYTES=150000;
function sha(bytes){return crypto.createHash('sha256').update(bytes).digest('hex');}
function snapshotObject(value,fields,complete=true){
  if (!value || typeof value!=='object' || Array.isArray(value)) return null;
  try{
    const proto=Object.getPrototypeOf(value);
    if(proto!==Object.prototype && proto!==null)return null;
    const keys=Reflect.ownKeys(value);
    if(complete ? keys.length!==fields.length :
      keys.some(k=>typeof k!=='string'||!fields.includes(k)))return null;
    if(keys.some(k=>typeof k!=='string'||!fields.includes(k)))return null;
    const desc=Object.getOwnPropertyDescriptors(value),out={};
    for(const f of (complete?fields:keys)){
      if(!desc[f]||!Object.hasOwn(desc[f],'value')||
         !desc[f].enumerable)return null;
      out[f]=desc[f].value;
    }
    return Object.freeze(out);
  }catch(_){return null;}
}
function snapshotDense(list){
  try{
    if(!Array.isArray(list))return null;
    const desc=Object.getOwnPropertyDescriptors(list);
    const length=desc.length?.value;
    if(!Number.isSafeInteger(length)||length<1||length>MAX_MEMBERS ||
       Reflect.ownKeys(list).length!==length+1)return null;
    const out=[];
    for(let i=0;i<length;i++){
      const entry=desc[String(i)];
      if(!entry||!Object.hasOwn(entry,'value')||!entry.enumerable ||
         typeof entry.value!=='string' ||
         Buffer.byteLength(entry.value,'utf8')>MAX_SIGNED_BYTES ||
         Buffer.from(entry.value,'utf8').toString('utf8')!==entry.value){
        return null;
      }
      out.push(entry.value);
    }
    return Object.freeze(out);
  }catch(_){return null;}
}
function payloadBytes(packet){
  const safe={};
  for(const key of PACKET_FIELDS)safe[key]=packet[key];
  return Buffer.concat([DOMAIN,Buffer.from(JSON.stringify(safe),'utf8')]);
}
function report(reason, first=0,last=0,count=0,digest=null){
  const good=reason==='GUARDIAN_HANDOFF_LOCAL_SIGNED_BATCH_VERIFIED';
  return Object.freeze({
    schemaVersion:1,kind:'GUARDIAN_SIGNED_BASELINE_HANDOFF_RESULT_V1',
    status:'SOURCE_ONLY_HOLD',
    authority:'OWNER_PINNED_PUBLIC_KEY_UNATTESTED',
    comparison:good?'LOCAL_SIGNED_HANDOFF_ONLY':'NOT_VERIFIED',
    reason,
    firstSequence:good?first:null,
    lastSequence:good?last:null,
    observedStatements:good?count:0,
    handoffSha256:good?digest:null,
    innerSignaturesLocallyVerified:good,
    externalAnchorVerified:false,
    durableCustodyVerified:false,
    historicalCompletenessVerified:false,
    durableAntiRollbackVerified:false,
    custodyVerified:false,
    liveness:'NOT_PROVEN',
    manualInterventionRequired:true,
    automaticRestartAllowed:false,
    activationAllowed:false,
    releaseAuthority:'NOT_ISSUED',
  });
}
function createGuardianSignedBaselineHandoff(options){
  const c=snapshotObject(options,KEY_FIELDS,false);
  if(!c||Object.keys(c).length!==KEY_FIELDS.length ||
     typeof c.expectedAnchorId!=='string'||!ANCHOR.test(c.expectedAnchorId)||
     typeof c.publicKeyPem!=='string'||
     typeof c.pinnedSpkiSha256!=='string'||
     !SHA.test(c.pinnedSpkiSha256)){
    throw new Error('GUARDIAN_HANDOFF_CONFIG_INVALID');
  }
  // G34 independently validates the exact G33 signer pin and algorithm.
  const observer=createGuardianSignedBaselineEquivocationVerifier(c);

  function prepareHandoff(inputs) {
    const entries=snapshotDense(inputs);
    if(!entries)return null;
    // A fresh temporary verifier validates signatures/order without
    // advancing the receiving witness or claiming prior history.
    const probe=createGuardianSignedBaselineEquivocationVerifier(c);
    const res=probe.observeBatch(entries);
    if(res.comparison!=='LOCAL_SIGNED_BATCH_ORDER_ONLY' ||
       !Number.isSafeInteger(res.firstSequence) ||
       !Number.isSafeInteger(res.lastSequence)){
      return null;
    }
    const partial={
      schemaVersion:1,kind:KIND,scope:SCOPE,
      anchorId:c.expectedAnchorId,
      pinnedSpkiSha256:c.pinnedSpkiSha256,
      statementCount:entries.length,
      firstSequence:res.firstSequence,
      lastSequence:res.lastSequence,
      statements:entries,
    };
    const packet={...partial,handoffSha256:sha(payloadBytes(partial))};
    const handoffJson=JSON.stringify(packet);
    if(Buffer.byteLength(handoffJson,'utf8')>MAX_TRANSPORT_BYTES)return null;
    return Object.freeze({
      schemaVersion:1,kind:'GUARDIAN_SIGNED_BASELINE_HANDOFF_PREPARED_V1',
      status:'SOURCE_ONLY_HOLD',
      handoffJson,
      handoffSha256:packet.handoffSha256,
      locallyVerifiedStatements:entries.length,
      externalAnchorVerified:false,
      durableCustodyVerified:false,
      historicalCompletenessVerified:false,
      durableAntiRollbackVerified:false,
      liveness:'NOT_PROVEN',
      activationAllowed:false,
      automaticRestartAllowed:false,
      releaseAuthority:'NOT_ISSUED',
    });
  }

  function verifyHandoff(raw) {
    if(typeof raw!=='string'||!raw.length ||
       Buffer.byteLength(raw,'utf8')>MAX_TRANSPORT_BYTES ||
       Buffer.from(raw,'utf8').toString('utf8')!==raw){
      return report('GUARDIAN_HANDOFF_TRANSPORT_INVALID');
    }
    let packet;
    try{
      packet=snapshotObject(
        parseUniqueKeySourceLock(Buffer.from(raw,'utf8')),ALL_FIELDS);
    }catch(_){return report('GUARDIAN_HANDOFF_TRANSPORT_INVALID');}
    if(!packet ||
       packet.schemaVersion!==1 || packet.kind!==KIND ||
       packet.scope!==SCOPE || packet.anchorId!==c.expectedAnchorId ||
       packet.pinnedSpkiSha256!==c.pinnedSpkiSha256 ||
       !Number.isSafeInteger(packet.statementCount) ||
       !Number.isSafeInteger(packet.firstSequence) ||
       !Number.isSafeInteger(packet.lastSequence) ||
       packet.firstSequence<1 ||
       packet.lastSequence<packet.firstSequence ||
       typeof packet.handoffSha256!=='string'||
       !SHA.test(packet.handoffSha256)){
      return report('GUARDIAN_HANDOFF_CONTRACT_INVALID');
    }
    const statements=snapshotDense(packet.statements);
    if(!statements||statements.length!==packet.statementCount){
      return report('GUARDIAN_HANDOFF_CONTRACT_INVALID');
    }
    const safe={...packet,statements};
    if(sha(payloadBytes(safe))!==packet.handoffSha256){
      return report('GUARDIAN_HANDOFF_TRANSPORT_DIGEST_MISMATCH');
    }
    // Check outer claims against parsed inner sequence fields BEFORE
    // mutating the witness. A recomputed untrusted transport checksum
    // must not let false first/last metadata poison the receiver.
    let firstClaim,lastClaim;
    try {
      firstClaim=parseUniqueKeySourceLock(Buffer.from(statements[0],'utf8')).sequence;
      lastClaim=parseUniqueKeySourceLock(
        Buffer.from(statements[statements.length-1],'utf8')).sequence;
    } catch (_) {
      return report('GUARDIAN_HANDOFF_INNER_SIGNATURES_UNVERIFIED');
    }
    if(!Number.isSafeInteger(firstClaim)||
       !Number.isSafeInteger(lastClaim)||
       packet.firstSequence!==firstClaim ||
       packet.lastSequence!==lastClaim){
      return report('GUARDIAN_HANDOFF_SEQUENCE_CLAIM_MISMATCH');
    }
    // The only mutating operation is G35's bounded, all-or-none in-memory
    // observeBatch. It validates EVERY inner signature anew. A failure
    // does not adopt a valid prefix, and contradictory valid signatures
    // permanently latch the receiver to local HOLD.
    const verdict=observer.observeBatch(statements);
    if(verdict.reason==='GUARDIAN_SIGNED_BASELINE_BATCH_EQUIVOCATION_OBSERVED'){
      return report('GUARDIAN_HANDOFF_SIGNED_EQUIVOCATION_OBSERVED');
    }
    if(verdict.reason==='GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED' ||
       verdict.reason==='GUARDIAN_SIGNED_BASELINE_MEMORY_LIMIT_REACHED'){
      return report('GUARDIAN_HANDOFF_WITNESS_LATCHED');
    }
    if(verdict.reason==='GUARDIAN_SIGNED_BASELINE_BATCH_REPLAY_OBSERVED'){
      return report('GUARDIAN_HANDOFF_SIGNED_REPLAY_OBSERVED');
    }
    if(verdict.reason==='GUARDIAN_SIGNED_BASELINE_BATCH_ROLLBACK_OBSERVED'){
      return report('GUARDIAN_HANDOFF_SIGNED_ROLLBACK_OBSERVED');
    }
    if(verdict.comparison!=='LOCAL_SIGNED_BATCH_ORDER_ONLY'){
      return report('GUARDIAN_HANDOFF_INNER_SIGNATURES_UNVERIFIED');
    }
    // Refuse a fabricated outer claim even if all inner signatures
    // are genuine. This contract should be checked *before* adoption;
    // shape claims derive from signed inner data and are not trusted.
    if(verdict.firstSequence!==packet.firstSequence ||
       verdict.lastSequence!==packet.lastSequence ||
       verdict.addedStatements!==packet.statementCount){
      return report('GUARDIAN_HANDOFF_SEQUENCE_CLAIM_MISMATCH');
    }
    return report('GUARDIAN_HANDOFF_LOCAL_SIGNED_BATCH_VERIFIED',
      verdict.firstSequence,verdict.lastSequence,
      verdict.observedStatements,packet.handoffSha256);
  }
  return Object.freeze({prepareHandoff,verifyHandoff});
}
module.exports=Object.freeze({createGuardianSignedBaselineHandoff});
