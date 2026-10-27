/**
 * Guardian G33: OFFLINE, READ-ONLY external baseline signature contract.
 *
 * Caller-supplied pinned Ed25519 public key and digest are NOT a live trust
 * registry. A signature MATCH is only a cryptographic match to the pinned
 * key and the locally read journal+ledger bytes. A previously approved,
 * independently protected trust anchor is outside this source-only module.
 *
 * No imports or constructors create keys, contact services or write files.
 * No Check, restart, HOLD release, recover, network or publication action.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createGuardianLocalDiagnostics } =
  require('./guardian-local-diagnostics.cjs');
const { generationLedgerName } =
  require('./guardian-local-receipt-journal.cjs');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');

const CONFIG = Object.freeze(['directory', 'fileName','expectedAnchorId',
  'publicKeyPem','pinnedSpkiSha256','maxBytes']);
const ENVELOPE = Object.freeze(['schemaVersion','kind','scope','anchorId',
  'sequence','observedAt','journalSha256','ledgerSha256','journalBytes',
  'ledgerBytes','algorithm','signatureBase64']);
const SIGNED = Object.freeze(ENVELOPE.filter(k => k !== 'signatureBase64'));
const JOURNAL = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const ANCHOR = /^[a-z][a-z0-9-]{3,63}$/;
const SHA = /^[a-f0-9]{64}$/;
const UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const KIND = 'GUARDIAN_EXTERNAL_GENERATION_BASELINE_V1';
const SCOPE = 'NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY';
const PREFIX = Buffer.from('NOHANDS_GUARDIAN_EXTERNAL_BASELINE_V1\n','utf8');
const MAX_PACKET_BYTES = 8192;
const MAX_SOURCE_BYTES = 10_485_760;
const ACCEPTED_REASONS = new Set([
  'GUARDIAN_DIAGNOSTICS_CLEAN_STOP',
  'GUARDIAN_DIAGNOSTICS_MANUAL_RECOVERY_REQUIRED',
  'GUARDIAN_DIAGNOSTICS_GENERATION_UNTERMINATED',
  'GUARDIAN_DIAGNOSTICS_CONCURRENT_GENERATION_OBSERVED',
  'GUARDIAN_DIAGNOSTICS_INCONCLUSIVE',
]);
function snapshotShape(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== names.length ||
        keys.some(k => typeof k !== 'string' || !names.includes(k))) return null;
    const desc = Object.getOwnPropertyDescriptors(value), out = {};
    for (const k of names) {
      if (!desc[k] || !Object.hasOwn(desc[k],'value') ||
          desc[k].enumerable !== true) return null;
      Object.defineProperty(out,k,{value:desc[k].value,
        enumerable:true,writable:false,configurable:false});
    }
    return Object.freeze(out);
  } catch (_) { return null; }
}
function configSnapshot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some(k => typeof k !== 'string' || !CONFIG.includes(k))) return null;
    const desc = Object.getOwnPropertyDescriptors(value), out = {};
    for (const key of keys) {
      if (!desc[key] || !Object.hasOwn(desc[key], 'value') ||
          !desc[key].enumerable) return null;
      out[key] = desc[key].value;
    }
    return Object.freeze(out);
  } catch (_) { return null; }
}
function checksum(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function validEnvelope(raw) {
  const packet=snapshotShape(raw,ENVELOPE);
  if (!packet || packet.schemaVersion!==1 || packet.kind!==KIND ||
      packet.scope!==SCOPE ||
      typeof packet.anchorId!=='string' || !ANCHOR.test(packet.anchorId) ||
      !Number.isSafeInteger(packet.sequence) ||
      packet.sequence < 1 ||
      typeof packet.observedAt!=='string' || !UTC.test(packet.observedAt) ||
      !Number.isFinite(Date.parse(packet.observedAt)) ||
      new Date(packet.observedAt).toISOString() !== packet.observedAt ||
      typeof packet.journalSha256!=='string' || !SHA.test(packet.journalSha256) ||
      typeof packet.ledgerSha256!=='string' || !SHA.test(packet.ledgerSha256) ||
      !Number.isSafeInteger(packet.journalBytes) || packet.journalBytes < 1 ||
      !Number.isSafeInteger(packet.ledgerBytes) || packet.ledgerBytes < 1 ||
      packet.algorithm!=='Ed25519' ||
      typeof packet.signatureBase64!=='string' ||
      packet.signatureBase64.length > 128) return null;
  const signature=Buffer.from(packet.signatureBase64,'base64');
  if (signature.length!==64 ||
      signature.toString('base64')!==packet.signatureBase64) return null;
  const signed={};
  for (const field of SIGNED) signed[field]=packet[field];
  return Object.freeze({packet,signed:Object.freeze(signed),signature});
}
function readProtected(filename,max) {
  let fd;
  try {
    fd=fs.openSync(filename,fs.constants.O_RDONLY |
      (fs.constants.O_NOFOLLOW ?? 0));
    const a=fs.fstatSync(fd);
    if (!a.isFile() || a.nlink!==1 || a.size<1 || a.size>max ||
        (a.mode & 0o077)!==0 ||
        (typeof process.getuid==='function' && a.uid!==process.getuid())) {
      return null;
    }
    const bytes=Buffer.alloc(a.size);
    let off=0;
    while(off<bytes.length) {
      const n=fs.readSync(fd,bytes,off,bytes.length-off,off);
      if (!Number.isSafeInteger(n) || n<=0) return null;
      off+=n;
    }
    const b=fs.fstatSync(fd), v=fs.lstatSync(filename);
    if (!b.isFile() || v.isSymbolicLink() || !v.isFile() ||
        v.nlink!==1 || (v.mode & 0o077)!==0 ||
        a.dev!==b.dev || a.ino!==b.ino || a.size!==b.size ||
        a.mtimeMs!==b.mtimeMs || a.ctimeMs!==b.ctimeMs ||
        v.dev!==a.dev || v.ino!==a.ino ||
        v.size!==a.size || v.mtimeMs!==a.mtimeMs ||
        v.ctimeMs!==a.ctimeMs ||
        bytes.at(-1)!==10 ||
        !Buffer.from(bytes.toString('utf8'),'utf8').equals(bytes)) return null;
    return Object.freeze({
      bytes, dev:a.dev, ino:a.ino,size:a.size,
      mtimeMs:a.mtimeMs,ctimeMs:a.ctimeMs,
      sha:checksum(bytes),
    });
  } catch (_) {return null;}
  finally {if(fd!==undefined) {try{fs.closeSync(fd);}catch(_){}}}
}
function sameRead(a,b) {
  return !!a && !!b && a.dev===b.dev && a.ino===b.ino &&
    a.size===b.size && a.mtimeMs===b.mtimeMs &&
    a.ctimeMs===b.ctimeMs && a.bytes.equals(b.bytes);
}
function result(reason, seq=0, localSha=null, ledgerSha=null,
  signedAnchorSha=null) {
  const match=reason==='GUARDIAN_EXTERNAL_BASELINE_SIGNATURE_AND_PAIR_MATCH';
  return Object.freeze({
    schemaVersion:1,kind:'GUARDIAN_EXTERNAL_BASELINE_COMPARISON_V1',
    status:'SOURCE_ONLY_HOLD',
    authority:'OWNER_PINNED_PUBLIC_KEY_UNATTESTED',
    comparison:match?'LOCAL_SIGNATURE_AND_PAIR_MATCH_ONLY':'NOT_VERIFIED',
    reason, anchorSequence:match?seq:0,
    journalSha256:match?localSha:null,
    ledgerSha256:match?ledgerSha:null,
    signedPayloadSha256:match?signedAnchorSha:null,
    pinnedSignerSignatureValid:match,
    externalAnchorVerified:false,
    historicalCompletenessVerified:false,
    custodyVerified:false,liveness:'NOT_PROVEN',
    manualInterventionRequired:true,
    automaticRestartAllowed:false,activationAllowed:false,
    releaseAuthority:'NOT_ISSUED',
  });
}
function createGuardianExternalBaselineVerifier(options) {
  const config=configSnapshot(options);
  if (!config || typeof config.directory!=='string' ||
      !path.isAbsolute(config.directory) ||
      typeof config.fileName!=='string' || !JOURNAL.test(config.fileName) ||
      typeof config.expectedAnchorId!=='string' ||
      !ANCHOR.test(config.expectedAnchorId) ||
      typeof config.publicKeyPem!=='string' ||
      !config.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n') ||
      !config.publicKeyPem.includes('\n-----END PUBLIC KEY-----') ||
      typeof config.pinnedSpkiSha256!=='string' ||
      !SHA.test(config.pinnedSpkiSha256)) {
    throw new Error('GUARDIAN_EXTERNAL_BASELINE_CONFIG_INVALID');
  }
  const max=config.maxBytes??1_048_576;
  if (!Number.isSafeInteger(max) || max<1024 ||
      max>MAX_SOURCE_BYTES) {
    throw new Error('GUARDIAN_EXTERNAL_BASELINE_CONFIG_INVALID');
  }
  let publicKey,pinnedDir,dirIdentity;
  try {
    publicKey=crypto.createPublicKey(config.publicKeyPem);
    if (publicKey.asymmetricKeyType!=='ed25519') throw new Error('key type');
    const spki=publicKey.export({format:'der',type:'spki'});
    if (checksum(spki)!==config.pinnedSpkiSha256) throw new Error('key pin mismatch');
    pinnedDir=fs.realpathSync(config.directory);
    const st=fs.lstatSync(pinnedDir);
    if (!st.isDirectory() || st.isSymbolicLink() ||
        (st.mode & 0o077)!==0 ||
        (typeof process.getuid==='function' && st.uid!==process.getuid())) {
      throw new Error('unsafe directory');
    }
    dirIdentity=Object.freeze({dev:st.dev,ino:st.ino});
  } catch (_) {throw new Error('GUARDIAN_EXTERNAL_BASELINE_PIN_UNVERIFIED');}
  const journal=path.join(pinnedDir,config.fileName);
  const ledger=path.join(pinnedDir,generationLedgerName(config.fileName));
  const controller=Object.freeze({status:()=>Object.freeze({
    state:'CREATED',pid:null,errorCode:null,generationId:null,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    automaticRestartAllowed:false,
  })});
  const diagnostics=createGuardianLocalDiagnostics({
    directory:pinnedDir,fileName:config.fileName,
    maxBytes:max,controller,
  });
  function trustedDir() {
    try{
      const st=fs.lstatSync(pinnedDir);
      return st.isDirectory() && !st.isSymbolicLink() &&
        st.dev===dirIdentity.dev && st.ino===dirIdentity.ino &&
        (st.mode & 0o077)===0 &&
        (typeof process.getuid!=='function' || st.uid===process.getuid()) &&
        fs.realpathSync(config.directory)===pinnedDir;
    }catch(_){return false;}
  }
  // Replay latch is only in this observer's RAM. A restarted instance
  // cannot establish an external monotonic sequence or durable custody.
  let lastSequence=0, latched=null;
  function verify(input) {
    if (latched) return result(latched);
    let normalized;
    try {
      if (typeof input!=='string' || !input.length ||
          Buffer.byteLength(input,'utf8')>MAX_PACKET_BYTES ||
          Buffer.from(input,'utf8').toString('utf8')!==input) {
        return result('GUARDIAN_EXTERNAL_BASELINE_INPUT_INVALID');
      }
      normalized=validEnvelope(parseUniqueKeySourceLock(
        Buffer.from(input,'utf8')));
    }catch(_) {return result('GUARDIAN_EXTERNAL_BASELINE_INPUT_INVALID');}
    if (!normalized) return result('GUARDIAN_EXTERNAL_BASELINE_ENVELOPE_INVALID');
    const {packet,signed,signature}=normalized;
    if (packet.anchorId!==config.expectedAnchorId) {
      return result('GUARDIAN_EXTERNAL_BASELINE_ANCHOR_ID_MISMATCH');
    }
    if (packet.sequence<=lastSequence) {
      return result('GUARDIAN_EXTERNAL_BASELINE_SEQUENCE_REPLAY');
    }
    const signedBytes=Buffer.concat([PREFIX,
      Buffer.from(JSON.stringify(signed),'utf8')]);
    if (!crypto.verify(null,signedBytes,publicKey,signature)) {
      return result('GUARDIAN_EXTERNAL_BASELINE_SIGNATURE_INVALID');
    }
    if (packet.journalBytes>max || packet.ledgerBytes>max || !trustedDir()) {
      return result('GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED');
    }
    // Local file+ledger recheck: A->B->Diagnostics->A'->B'.
    const first=[readProtected(journal,max),readProtected(ledger,max)];
    if (first.some(x=>!x)) {
      return result('GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED');
    }
    if (first[0].sha!==packet.journalSha256 ||
        first[1].sha!==packet.ledgerSha256 ||
        first[0].size!==packet.journalBytes ||
        first[1].size!==packet.ledgerBytes) {
      return result('GUARDIAN_EXTERNAL_BASELINE_PAIR_MISMATCH');
    }
    const inspected=diagnostics.inspect();
    const second=[readProtected(journal,max),readProtected(ledger,max)];
    if (!trustedDir() || !sameRead(first[0],second[0]) ||
        !sameRead(first[1],second[1])) {
      return result('GUARDIAN_EXTERNAL_BASELINE_PAIR_CHANGED_DURING_READ');
    }
    if (!ACCEPTED_REASONS.has(inspected.reason) ||
        inspected.journalSha256!==first[0].sha) {
      return result('GUARDIAN_EXTERNAL_BASELINE_RECONCILIATION_UNVERIFIED');
    }
    lastSequence=packet.sequence;
    return result('GUARDIAN_EXTERNAL_BASELINE_SIGNATURE_AND_PAIR_MATCH',
      packet.sequence,first[0].sha,first[1].sha,checksum(signedBytes));
  }
  return Object.freeze({verify});
}
module.exports=Object.freeze({createGuardianExternalBaselineVerifier});
