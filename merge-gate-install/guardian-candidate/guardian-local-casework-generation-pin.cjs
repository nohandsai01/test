/**
 * Guardian G41: opt-in, read-only Casework V2 local association claim.
 *
 * A caller-supplied manifest pins one actual V1 QUARANTINED casework receipt
 * to one actual Generation V2 FAILED terminal event and its launch ledger.
 * All named records must be present in protected, independently re-read local
 * journals. A checksum detects accidental claim corruption, NOT forgery:
 * no signer, identity, causal link, custody, liveness, or release is proven.
 *
 * Import/construction do not read disk, write, spawn or communicate.
 */
'use strict';

const crypto=require('node:crypto');

const SHA=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const GENERATION=/^[a-f0-9]{32}$/;
const CLAIM_KEYS=Object.freeze([
  'schemaVersion','kind','caseworkReceiptId','bundleSha256',
  'caseworkJournalSha256','terminalEventId','generationId',
  'terminalJournalSha256','launchLedgerSha256',
]);
// Backwards-compatible G42 claim extension: pin canonical selectedFailure
// content, not only its eventId and the encompassing local journal bytes.
const CONTENT_CLAIM_KEYS=Object.freeze([
  ...CLAIM_KEYS.slice(0,CLAIM_KEYS.indexOf('generationId')),
  'terminalEventSha256',
  ...CLAIM_KEYS.slice(CLAIM_KEYS.indexOf('generationId')),
]);
const TIMESTAMP=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const ERROR_CODE=/^GUARDIAN_[A-Z0-9_]{1,100}$/;
const COUNTS=Object.freeze(['receipts','quarantined','duplicates',
  'rejected','handoffs','returns']);
const CORRELATED=Object.freeze([
  'schemaVersion','kind','authority','status','classification','reason',
  'priority','caseworkJournalSha256','terminalJournalSha256',
  'orderedEventsSha256','caseworkCounts','terminalFailures',
  'unterminatedGenerations','crossJournalBinding',
  'generationLedgerBinding','custodyVerified','liveness',
  'manualInterventionRequired','automaticRestartAllowed',
  'activationAllowed','releaseAuthority',
]);
const RECEIPT=Object.freeze([
  'schemaVersion','kind','status','authority','result','reason',
  'caseworkReceiptId','bundleSha256','journalSha256','custodyVerified',
  'liveness','manualInterventionRequired','automaticRestartAllowed',
  'activationAllowed','releaseAuthority',
]);
const PACKET=Object.freeze([
  'schemaVersion','kind','authority','status','availability','reason',
  'sourceReason','processState','liveness','manualInterventionRequired',
  'journalEntries','journalSha256','failureCount','eventSequence',
  'generationId','launchLedgerSha256','selectedFailure','previousReceipt',
  'nextReceipt','firstFailure','latestFailure','automaticRestartAllowed',
  'activationAllowed','releaseAuthority','evidenceSha256',
]);
const EVENT=Object.freeze(['eventId','timestamp','state','errorCode',
  'generationId']);
const COMPARISON=Object.freeze([
  'schemaVersion','kind','status','comparison','reason','inspectedEntries',
  'journalSha256','custodyVerified','controllerStateVerified','liveness',
  'manualInterventionRequired','automaticRestartAllowed','activationAllowed',
  'releaseAuthority',
]);

function exact(raw,keys) {
  try {
    if (!raw || typeof raw!=='object' || Array.isArray(raw)) return null;
    const proto=Object.getPrototypeOf(raw);
    if (proto!==Object.prototype && proto!==null) return null;
    const desc=Object.getOwnPropertyDescriptors(raw), names=Reflect.ownKeys(raw);
    if (names.length!==keys.length ||
        names.some(k=>typeof k!=='string' || !keys.includes(k))) return null;
    const out={};
    for (const key of keys) {
      const d=desc[key];
      if (!d || !Object.hasOwn(d,'value') || !d.enumerable) return null;
      Object.defineProperty(out,key,{value:d.value,enumerable:true});
    }
    return Object.freeze(out);
  } catch (_) {return null;}
}
function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}
function snapshotClaim(raw) {
  // One descriptor snapshot only. Trying two successive exact() snapshots
  // would allow a stateful Proxy to change its visible shape between them.
  try {
    if (!raw || typeof raw!=='object' || Array.isArray(raw)) return null;
    const proto=Object.getPrototypeOf(raw);
    if (proto!==Object.prototype && proto!==null) return null;
    const desc=Object.getOwnPropertyDescriptors(raw);
    const names=Reflect.ownKeys(desc);
    const keys=names.length===CONTENT_CLAIM_KEYS.length+1?
      CONTENT_CLAIM_KEYS:CLAIM_KEYS;
    const expected=[...keys,'claimSha256'];
    if (names.length!==expected.length ||
        names.some(k=>typeof k!=='string' || !expected.includes(k))) {
      return null;
    }
    const out={};
    for (const key of expected) {
      const d=desc[key];
      if (!d || !Object.hasOwn(d,'value') || !d.enumerable) return null;
      Object.defineProperty(out,key,{value:d.value,enumerable:true});
    }
    return Object.freeze(out);
  } catch (_) {return null;}
}
function parseClaim(raw) {
  const x=snapshotClaim(raw);
  const hasContentPin=!!x && Object.hasOwn(x,'terminalEventSha256');
  if (!x || x.schemaVersion!==2 ||
      x.kind!=='GUARDIAN_CASEWORK_GENERATION_CLAIM_V2' ||
      !UUID.test(x.caseworkReceiptId??'') ||
      !UUID.test(x.terminalEventId??'') ||
      !GENERATION.test(x.generationId??'') ||
      (hasContentPin && !SHA.test(x.terminalEventSha256??'')) ||
      ['bundleSha256','caseworkJournalSha256','terminalJournalSha256',
        'launchLedgerSha256','claimSha256'].some(k=>!SHA.test(x[k]??''))) {
    return null;
  }
  const pinned={};
  for (const key of hasContentPin?CONTENT_CLAIM_KEYS:CLAIM_KEYS) {
    pinned[key]=x[key];
  }
  return hash(pinned)===x.claimSha256?x:null;
}
function selectedEventHash(event) {
  if (!event || typeof event.timestamp!=='string' ||
      !TIMESTAMP.test(event.timestamp) ||
      !Number.isFinite(Date.parse(event.timestamp)) ||
      !(event.errorCode===null ||
        (typeof event.errorCode==='string' &&
         ERROR_CODE.test(event.errorCode)))) return null;
  const canonical={};
  for (const field of EVENT) canonical[field]=event[field];
  return hash(canonical);
}
function hold(x) {
  return x && x.status==='SOURCE_ONLY_HOLD' &&
    x.authority==='LOCAL_UNAUTHENTICATED_OBSERVATION' &&
    x.liveness==='NOT_PROVEN' &&
    x.custodyVerified===false && x.manualInterventionRequired===true &&
    x.automaticRestartAllowed===false && x.activationAllowed===false &&
    x.releaseAuthority==='NOT_ISSUED';
}
function caseSnapshot(raw) {
  const x=exact(raw,CORRELATED), counts=exact(x?.caseworkCounts,COUNTS);
  if (!hold(x) || !counts || x.schemaVersion!==1 ||
      x.kind!=='GUARDIAN_CASEWORK_GENERATION_ASSESSMENT_V1' ||
      x.classification!=='LOCAL_COINCIDENT_OBSERVATIONS_ONLY' ||
      x.crossJournalBinding!=='NOT_PROVEN' ||
      x.generationLedgerBinding!=='NOT_PROVEN' ||
      !SHA.test(x.caseworkJournalSha256??'') ||
      !SHA.test(x.terminalJournalSha256??'') ||
      !SHA.test(x.orderedEventsSha256??'') ||
      !Number.isSafeInteger(x.terminalFailures) ||
      x.terminalFailures<1 || x.terminalFailures>4096 ||
      !Number.isSafeInteger(x.unterminatedGenerations) ||
      x.unterminatedGenerations<0 || x.unterminatedGenerations>4096 ||
      !Number.isSafeInteger(counts.quarantined) ||
      counts.quarantined<1 || counts.quarantined>4096 ||
      COUNTS.some(k=>!Number.isSafeInteger(counts[k]) ||
        counts[k]<0 || counts[k]>4096)) return null;
  return Object.freeze({
    casework:x.caseworkJournalSha256,
    terminal:x.terminalJournalSha256,
    ordered:x.orderedEventsSha256,
    failures:x.terminalFailures,
    generations:x.unterminatedGenerations,
    counts:Object.freeze(counts),
  });
}
function receiptSnapshot(raw) {
  const x=exact(raw,RECEIPT);
  if (!hold(x) || x.schemaVersion!==2 ||
      x.kind!=='GUARDIAN_CASEWORK_RECEIPT_OBSERVATION_V2' ||
      x.result!=='LOCAL_QUARANTINE_OBSERVED_ONLY' ||
      x.reason!=='GUARDIAN_CASEWORK_PIN_LOCAL_RECORD_MATCH' ||
      !UUID.test(x.caseworkReceiptId??'') ||
      !SHA.test(x.bundleSha256??'') ||
      !SHA.test(x.journalSha256??'')) return null;
  return Object.freeze({id:x.caseworkReceiptId,
    bundle:x.bundleSha256,journal:x.journalSha256});
}
function snapshotPacket(raw) {
  const x=exact(raw,PACKET);
  if (!x) return null;
  const events={};
  for (const field of ['selectedFailure','previousReceipt','nextReceipt',
    'firstFailure','latestFailure']) {
    events[field]=x[field]===null?null:exact(x[field],EVENT);
    if (x[field]!==null && !events[field]) return null;
  }
  return Object.freeze({...x,...events});
}
function evidenceSnapshot(packet, rawComparison) {
  try {
    const comparison=exact(rawComparison,COMPARISON);
    // Comparison is a separately re-read, protected file verification, not
    // a self-consistent checksum handed to us by the manifest submitter.
    if (!comparison || comparison.comparison!=='MATCH_LOCAL_SNAPSHOT_ONLY' ||
        comparison.kind!=='GUARDIAN_LOCAL_EVIDENCE_COMPARISON_V1' ||
        comparison.status!=='SOURCE_ONLY_HOLD' ||
        comparison.custodyVerified!==false ||
        comparison.activationAllowed!==false ||
        comparison.releaseAuthority!=='NOT_ISSUED' ||
        !SHA.test(comparison.journalSha256??'')) return null;
    if (!packet || packet.schemaVersion!==2 ||
        packet.kind!=='GUARDIAN_LOCAL_FAULT_EVIDENCE_V2' ||
        packet.status!=='SOURCE_ONLY_HOLD' ||
        packet.authority!=='LOCAL_UNAUTHENTICATED_OBSERVATION' ||
        packet.availability!=='LOCAL_SNAPSHOT' ||
        packet.reason!=='GUARDIAN_EVIDENCE_FAULT_RECORDED' ||
        packet.activationAllowed!==false ||
        packet.releaseAuthority!=='NOT_ISSUED' ||
        !SHA.test(packet.evidenceSha256??'') ||
        !SHA.test(packet.journalSha256??'') ||
        !SHA.test(packet.launchLedgerSha256??'') ||
        !GENERATION.test(packet.generationId??'') ||
        !UUID.test(packet.selectedFailure?.eventId??'') ||
        packet.selectedFailure?.state!=='FAILED' ||
        packet.selectedFailure?.generationId!==packet.generationId ||
        packet.journalSha256!==comparison.journalSha256) return null;
    const eventContentSha256=selectedEventHash(packet.selectedFailure);
    if (!eventContentSha256) return null;
    return Object.freeze({
      event:packet.selectedFailure.eventId,generation:packet.generationId,
      journal:packet.journalSha256,ledger:packet.launchLedgerSha256,
      packet:packet.evidenceSha256,eventContentSha256,
      failureCount:packet.failureCount,
    });
  } catch (_) {return null;}
}
function fail(reason) {
  return Object.freeze({
    schemaVersion:2,kind:'GUARDIAN_CASEWORK_GENERATION_PIN_ASSESSMENT_V2',
    status:'SOURCE_ONLY_HOLD',
    authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    classification:'NOT_VERIFIED',reason,priority:'P0',
    claimSha256:null,caseworkJournalSha256:null,
    terminalJournalSha256:null,launchLedgerSha256:null,
    crossJournalBinding:'NOT_PROVEN',generationLedgerBinding:'NOT_PROVEN',
    custodyVerified:false,liveness:'NOT_PROVEN',
    manualInterventionRequired:true,automaticRestartAllowed:false,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  });
}
function same(a,b) {
  return !!a && !!b && JSON.stringify(a)===JSON.stringify(b);
}
function createGuardianCaseworkGenerationPinAssessment(options) {
  const x=exact(options,['caseworkDiagnostics','correlation','operator']);
  if (!x || typeof x.caseworkDiagnostics?.inspectQuarantinedReceipt!=='function' ||
      typeof x.correlation?.assess!=='function' ||
      typeof x.operator?.incidentEvidence!=='function' ||
      typeof x.operator?.verifyIncidentEvidence!=='function') {
    throw new Error('GUARDIAN_CASEWORK_GENERATION_PIN_CONFIG_INVALID');
  }
  function assess(rawClaim) {
    const claim=parseClaim(rawClaim);
    if (!claim) return fail('GUARDIAN_CASEWORK_GENERATION_CLAIM_INVALID');
    let a,b,c,d,e,f,g,h;
    try {
      const request=Object.freeze({
        receiptId:claim.caseworkReceiptId,
        journalSha256:claim.caseworkJournalSha256,
      });
      const event=Object.freeze({
        eventId:claim.terminalEventId,
        journalSha256:claim.terminalJournalSha256,
      });
      a=caseSnapshot(x.correlation.assess());
      b=receiptSnapshot(x.caseworkDiagnostics.inspectQuarantinedReceipt(request));
      const p0=snapshotPacket(x.operator.incidentEvidence(event));
      c=p0?evidenceSnapshot(p0,x.operator.verifyIncidentEvidence(p0)):null;
      d=caseSnapshot(x.correlation.assess());
      e=receiptSnapshot(x.caseworkDiagnostics.inspectQuarantinedReceipt(request));
      const p1=snapshotPacket(x.operator.incidentEvidence(event));
      f=p1?evidenceSnapshot(p1,x.operator.verifyIncidentEvidence(p1)):null;
    } catch (_) {return fail('GUARDIAN_CASEWORK_GENERATION_PIN_READ_FAILED');}
    if (!same(a,d) || !same(b,e) || !same(c,f) ||
        !a || !b || !c ||
        a.casework!==claim.caseworkJournalSha256 ||
        a.terminal!==claim.terminalJournalSha256 ||
        a.failures!==c.failureCount ||
        b.id!==claim.caseworkReceiptId ||
        b.bundle!==claim.bundleSha256 ||
        b.journal!==claim.caseworkJournalSha256 ||
        c.event!==claim.terminalEventId ||
        c.generation!==claim.generationId ||
        c.journal!==claim.terminalJournalSha256 ||
        c.ledger!==claim.launchLedgerSha256 ||
        (Object.hasOwn(claim,'terminalEventSha256') &&
         c.eventContentSha256!==claim.terminalEventSha256)) {
      return fail('GUARDIAN_CASEWORK_GENERATION_PIN_MISMATCH');
    }
    return Object.freeze({
      schemaVersion:2,kind:'GUARDIAN_CASEWORK_GENERATION_PIN_ASSESSMENT_V2',
      status:'SOURCE_ONLY_HOLD',
      authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
      classification:'LOCAL_UNTRUSTED_MANIFEST_PINS_MATCH_ONLY',
      reason:'GUARDIAN_CASEWORK_GENERATION_PIN_LOCAL_MATCH',
      priority:'P1',
      claimSha256:claim.claimSha256,
      caseworkJournalSha256:a.casework,
      terminalJournalSha256:a.terminal,
      launchLedgerSha256:c.ledger,
      ...(Object.hasOwn(claim,'terminalEventSha256') ? {
        terminalEventSha256:c.eventContentSha256,
        eventContentBinding:'LOCAL_UNAUTHENTICATED_CONTENT_MATCH_ONLY',
      } : {}),
      crossJournalBinding:'LOCAL_UNAUTHENTICATED_PIN_MATCH_ONLY',
      generationLedgerBinding:'LOCAL_V2_FAULT_AND_LEDGER_MATCH_ONLY',
      custodyVerified:false,liveness:'NOT_PROVEN',
      manualInterventionRequired:true,automaticRestartAllowed:false,
      activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    });
  }
  return Object.freeze({assess});
}
module.exports=Object.freeze({createGuardianCaseworkGenerationPinAssessment});
