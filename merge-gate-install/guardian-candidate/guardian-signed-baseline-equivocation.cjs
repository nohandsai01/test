/**
 * NO HANDS AI Guardian G34 — OFFLINE signed external-baseline equivocation.
 *
 * Compares signatures over G33's exact canonical envelope, including
 * identical-sequence conflicting signed assertions. This is NOT an
 * authorized anchor, proof of external custody, append-only service or
 * persistent anti-rollback. Import/constructor/compare/observe do no IO.
 *
 * Caller-supplied public-key pins are NOT independently trusted.
 * The in-memory observer is bounded and permanent-HOLD on equivocation.
 */
'use strict';

const crypto = require('node:crypto');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');

const CONFIG = Object.freeze([
  'expectedAnchorId', 'publicKeyPem', 'pinnedSpkiSha256',
]);
const FIELDS = Object.freeze([
  'schemaVersion','kind','scope','anchorId','sequence',
  'observedAt','journalSha256','ledgerSha256','journalBytes',
  'ledgerBytes','algorithm','signatureBase64',
]);
const SIGNED = Object.freeze(FIELDS.slice(0,-1));
const KIND = 'GUARDIAN_EXTERNAL_GENERATION_BASELINE_V1';
const SCOPE = 'NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY';
const PREFIX = Buffer.from('NOHANDS_GUARDIAN_EXTERNAL_BASELINE_V1\n');
const SHA = /^[0-9a-f]{64}$/;
const ANCHOR = /^[a-z][a-z0-9-]{3,63}$/;
const UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const MAX_BYTES = 8192;
const MAX_OBSERVATIONS = 64;
const MAX_BATCH = 16;

function ownData(value, allowed, requireAll) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const names = Reflect.ownKeys(value);
    if ((requireAll && names.length !== allowed.length) ||
        names.some(k => typeof k !== 'string' || !allowed.includes(k))) {
      return null;
    }
    const fields = Object.getOwnPropertyDescriptors(value);
    const copy = {};
    for (const name of (requireAll ? allowed : names)) {
      if (!fields[name] ||
          !Object.hasOwn(fields[name], 'value') ||
          !fields[name].enumerable) return null;
      copy[name] = fields[name].value;
    }
    return Object.freeze(copy);
  } catch (_) { return null; }
}
function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function output(reason, left = null, right = null, count = 0) {
  const order = reason === 'GUARDIAN_SIGNED_BASELINE_MONOTONIC_ORDER_OBSERVED';
  const conflict = reason === 'GUARDIAN_SIGNED_BASELINE_EQUIVOCATION_OBSERVED';
  const replay = reason === 'GUARDIAN_SIGNED_BASELINE_REPLAY_OBSERVED';
  const rollback = reason === 'GUARDIAN_SIGNED_BASELINE_ROLLBACK_OBSERVED';
  const verified = order || conflict || replay || rollback;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'GUARDIAN_SIGNED_BASELINE_EQUIVOCATION_V1',
    status: 'SOURCE_ONLY_HOLD',
    authority: 'OWNER_PINNED_PUBLIC_KEY_UNATTESTED',
    comparison: order ? 'LOCAL_SIGNED_ORDER_ONLY' :
      conflict ? 'LOCAL_SIGNED_CONFLICT_ONLY' :
      replay ? 'LOCAL_SIGNED_REPLAY_ONLY' :
      rollback ? 'LOCAL_SIGNED_ROLLBACK_ONLY' : 'NOT_VERIFIED',
    reason,
    earlierSequence: verified ? left.sequence : null,
    laterSequence: verified ? right.sequence : null,
    earlierSignedSha256: verified ? left.digest : null,
    laterSignedSha256: verified ? right.digest : null,
    locallyVerifiedSignatures: verified,
    witnessedStatements: count,
    externalAnchorVerified: false,
    historicalCompletenessVerified: false,
    custodyVerified: false,
    durableAntiRollbackVerified: false,
    liveness: 'NOT_PROVEN',
    manualInterventionRequired: true,
    automaticRestartAllowed: false,
    activationAllowed: false,
    releaseAuthority: 'NOT_ISSUED',
  });
}
function createGuardianSignedBaselineEquivocationVerifier(options) {
  const config = ownData(options, CONFIG, false);
  if (!config ||
      Object.keys(config).length !== CONFIG.length ||
      typeof config.expectedAnchorId !== 'string' ||
      !ANCHOR.test(config.expectedAnchorId) ||
      typeof config.publicKeyPem !== 'string' ||
      !config.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----\n') ||
      !config.publicKeyPem.includes('\n-----END PUBLIC KEY-----') ||
      typeof config.pinnedSpkiSha256 !== 'string' ||
      !SHA.test(config.pinnedSpkiSha256)) {
    throw new Error('GUARDIAN_EQUIVOCATION_CONFIG_INVALID');
  }
  let key;
  try {
    key = crypto.createPublicKey(config.publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519' ||
        sha256(key.export({type:'spki',format:'der'})) !==
          config.pinnedSpkiSha256) throw new Error('key mismatch');
  } catch (_) { throw new Error('GUARDIAN_EQUIVOCATION_KEY_PIN_UNVERIFIED'); }

  function parse(input) {
    if (typeof input !== 'string' || input.length === 0 ||
        Buffer.byteLength(input,'utf8') > MAX_BYTES) return null;
    try {
      const encoded = Buffer.from(input,'utf8');
      if (encoded.toString('utf8') !== input) return null;
      const v = ownData(parseUniqueKeySourceLock(encoded), FIELDS, true);
      if (!v || v.schemaVersion !== 1 || v.kind !== KIND ||
          v.scope !== SCOPE ||
          typeof v.anchorId !== 'string' ||
          v.anchorId !== config.expectedAnchorId ||
          !Number.isSafeInteger(v.sequence) || v.sequence < 1 ||
          typeof v.observedAt !== 'string' || !UTC.test(v.observedAt) ||
          !Number.isFinite(Date.parse(v.observedAt)) ||
          new Date(v.observedAt).toISOString() !== v.observedAt ||
          typeof v.journalSha256 !== 'string' ||
          !SHA.test(v.journalSha256) ||
          typeof v.ledgerSha256 !== 'string' || !SHA.test(v.ledgerSha256) ||
          !Number.isSafeInteger(v.journalBytes) || v.journalBytes < 1 ||
          !Number.isSafeInteger(v.ledgerBytes) || v.ledgerBytes < 1 ||
          v.algorithm !== 'Ed25519' ||
          typeof v.signatureBase64 !== 'string' ||
          v.signatureBase64.length > 128) return null;
      const signature=Buffer.from(v.signatureBase64,'base64');
      if (signature.length !== 64 ||
          signature.toString('base64') !== v.signatureBase64) return null;
      const unsigned = {};
      for (const field of SIGNED) unsigned[field] = v[field];
      const payload = Buffer.concat([PREFIX,
        Buffer.from(JSON.stringify(unsigned),'utf8')]);
      if (!crypto.verify(null,payload,key,signature)) return null;
      return Object.freeze({
        sequence: v.sequence,
        digest: sha256(payload),
      });
    } catch (_) { return null; }
  }
  function compare(left, right) {
    const a = parse(left), b = parse(right);
    if (!a || !b) return output('GUARDIAN_SIGNED_BASELINE_INPUT_UNVERIFIED');
    if (a.sequence === b.sequence) {
      return output(a.digest === b.digest ?
        'GUARDIAN_SIGNED_BASELINE_REPLAY_OBSERVED' :
        'GUARDIAN_SIGNED_BASELINE_EQUIVOCATION_OBSERVED', a, b);
    }
    return output(b.sequence > a.sequence ?
      'GUARDIAN_SIGNED_BASELINE_MONOTONIC_ORDER_OBSERVED' :
      'GUARDIAN_SIGNED_BASELINE_ROLLBACK_OBSERVED', a, b);
  }

  // Monotonic memory-only observation; no eviction, because eviction
  // could turn a prior signature conflict into a new apparent baseline.
  const seen = new Map();
  let maximum = 0, last = null, latched = false;
  function observe(input) {
    if (latched) return output('GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED',
      null,null,seen.size);
    const v = parse(input);
    if (!v) return output('GUARDIAN_SIGNED_BASELINE_INPUT_UNVERIFIED',
      null,null,seen.size);
    const prior = seen.get(v.sequence);
    if (prior) {
      if (prior.digest !== v.digest) {
        latched = true;
        return output('GUARDIAN_SIGNED_BASELINE_EQUIVOCATION_OBSERVED',
          prior,v,seen.size);
      }
      return output('GUARDIAN_SIGNED_BASELINE_REPLAY_OBSERVED',
        prior,v,seen.size);
    }
    if (v.sequence <= maximum) {
      return output('GUARDIAN_SIGNED_BASELINE_ROLLBACK_OBSERVED',
        last,v,seen.size);
    }
    if (seen.size >= MAX_OBSERVATIONS) {
      latched = true;
      return output('GUARDIAN_SIGNED_BASELINE_MEMORY_LIMIT_REACHED',
        null,null,seen.size);
    }
    if (!last) {
      seen.set(v.sequence,v);
      last=v;maximum=v.sequence;
      return output('GUARDIAN_SIGNED_BASELINE_FIRST_UNANCHORED_OBSERVATION',
        null,null,seen.size);
    }
    const priorLast = last;
    seen.set(v.sequence,v);
    last=v;maximum=v.sequence;
    return output('GUARDIAN_SIGNED_BASELINE_MONOTONIC_ORDER_OBSERVED',
      priorLast,v,seen.size);
  }
  // G35: snapshot every array member without invoking any accessor or
  // array iterator, even on Proxy/hostile inputs. Validate the WHOLE batch
  // before modifying the same-instance witness, so a malformed tail
  // cannot silently record a valid prefix as accepted.
  function cleanBatch(input) {
    try {
      if (!Array.isArray(input)) return null;
      const descriptors = Object.getOwnPropertyDescriptors(input);
      const length = descriptors.length?.value;
      if (!Number.isSafeInteger(length) || length < 1 ||
          length > MAX_BATCH ||
          Reflect.ownKeys(input).length !== length + 1) return null;
      const values=[];
      for(let i=0;i<length;i++) {
        const key=String(i), entry=descriptors[key];
        if (!entry || !Object.hasOwn(entry,'value') ||
            entry.enumerable !== true ||
            typeof entry.value !== 'string') return null;
        values.push(entry.value);
      }
      return values;
    } catch (_) { return null; }
  }
  function batchOutcome(reason, count, added = 0, first = null, end = null) {
    const accepted = reason ===
        'GUARDIAN_SIGNED_BASELINE_BATCH_LOCAL_ORDER_OBSERVED' ||
      reason ===
        'GUARDIAN_SIGNED_BASELINE_BATCH_FIRST_UNANCHORED_OBSERVATION';
    return Object.freeze({
      schemaVersion:1,
      kind:'GUARDIAN_SIGNED_BASELINE_BATCH_V1',
      status:'SOURCE_ONLY_HOLD',
      authority:'OWNER_PINNED_PUBLIC_KEY_UNATTESTED',
      comparison:accepted?'LOCAL_SIGNED_BATCH_ORDER_ONLY':'NOT_VERIFIED',
      reason,
      observedStatements:count,
      addedStatements:accepted?added:0,
      firstSequence:accepted?first.sequence:null,
      lastSequence:accepted?end.sequence:null,
      locallyVerifiedSignatures:accepted,
      externalAnchorVerified:false,
      historicalCompletenessVerified:false,
      custodyVerified:false,
      durableAntiRollbackVerified:false,
      liveness:'NOT_PROVEN',
      manualInterventionRequired:true,
      automaticRestartAllowed:false,
      activationAllowed:false,
      releaseAuthority:'NOT_ISSUED',
    });
  }
  function observeBatch(input) {
    if (latched) return batchOutcome(
      'GUARDIAN_SIGNED_BASELINE_CONFLICT_LATCHED',seen.size);
    const inputs=cleanBatch(input);
    if (!inputs) return batchOutcome(
      'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID',seen.size);
    // Parse/signature-verify ALL statements before evaluating any.
    const signed=inputs.map(parse);
    if (signed.some(x=>x===null)) return batchOutcome(
      'GUARDIAN_SIGNED_BASELINE_BATCH_INVALID',seen.size);
    const staged=new Map(seen);
    let highest=maximum;
    for(const statement of signed) {
      const prior=staged.get(statement.sequence);
      if (prior) {
        if (prior.digest !== statement.digest) {
          // Both signatures are valid for the same anchor+sequence;
          // observed equivocation is sticky, but no part of this batch
          // is committed to the witness map.
          latched=true;
          return batchOutcome(
            'GUARDIAN_SIGNED_BASELINE_BATCH_EQUIVOCATION_OBSERVED',seen.size);
        }
        return batchOutcome(
          'GUARDIAN_SIGNED_BASELINE_BATCH_REPLAY_OBSERVED',seen.size);
      }
      if (statement.sequence <= highest) return batchOutcome(
        'GUARDIAN_SIGNED_BASELINE_BATCH_ROLLBACK_OBSERVED',seen.size);
      staged.set(statement.sequence,statement);
      highest=statement.sequence;
    }
    if(staged.size>MAX_OBSERVATIONS){
      // Do not evict earlier evidence to hide future conflicts.
      latched=true;
      return batchOutcome(
        'GUARDIAN_SIGNED_BASELINE_MEMORY_LIMIT_REACHED',seen.size);
    }
    for(const v of signed)seen.set(v.sequence,v);
    const startedWithNone=last===null;
    last=signed[signed.length-1];
    maximum=last.sequence;
    return batchOutcome(startedWithNone ?
      'GUARDIAN_SIGNED_BASELINE_BATCH_FIRST_UNANCHORED_OBSERVATION' :
      'GUARDIAN_SIGNED_BASELINE_BATCH_LOCAL_ORDER_OBSERVED',
      seen.size,signed.length,signed[0],last);
  }
  return Object.freeze({compare,observe,observeBatch});
}
module.exports=Object.freeze({createGuardianSignedBaselineEquivocationVerifier});
