/**
 * G38: optional, owner-pinned Operator-only cross-journal observation.
 * Reads existing passive casework, generation-aware runtime, redacted brief,
 * and complete terminal event audit without owning ANY writer/control API.
 * There is deliberately no claim that casework bundle digests bind to the
 * Generation V2 ledger; that relationship is not in the V1 receipt format.
 */
'use strict';

const crypto = require('node:crypto');

const SHA = /^[a-f0-9]{64}$/;
const PRIORITIES = new Set(['P0','P1','P2','P3']);
const STATES = new Set(['CREATED','STARTING','RUNNING','STOPPING','STOPPED','FAILED']);
const CASE_KEYS = ['schemaVersion','kind','status','authority','result',
  'reason','journalState','lockState','journalSha256','counts',
  'liveness','custodyVerified','manualInterventionRequired',
  'automaticRestartAllowed','activationAllowed','releaseAuthority'];
const COUNT_KEYS = ['receipts','quarantined','duplicates','rejected','handoffs','returns'];
const RUNTIME_KEYS = ['schemaVersion','kind','authority','status','priority',
  'classification','nextAction','processState','triageReason','healthFreshness',
  'healthReason','healthSampleAgeMs','healthMaxAgeMs','journalSha256',
  'journalEntries','historicalFailureCount','liveness',
  'manualInterventionRequired','automaticRestartAllowed','activationAllowed',
  'releaseAuthority'];
const BRIEF_KEYS = ['schemaVersion','kind','authority','status','classification',
  'priority','processState','sourceReason','healthFreshness','journalSha256',
  'journalEntries','historicalFailureCount','events','liveness',
  'manualInterventionRequired','automaticRestartAllowed','activationAllowed',
  'releaseAuthority','briefSha256'];
const AUDIT_KEYS = ['schemaVersion','kind','authority','status','comparison',
  'reason','journalSha256','orderedEventsSha256','processState',
  'inspectedEntries','inspectedPages','failureCount','failureCodes',
  'firstFailure','latestFailure','lastTerminal','liveness',
  'manualInterventionRequired','automaticRestartAllowed','activationAllowed',
  'releaseAuthority'];
const EVENT_KEYS = ['eventId','timestamp','state','errorCode'];
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const CODE = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
function exact(raw, keys, optional=[]) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  try {
    const proto=Object.getPrototypeOf(raw);
    if (proto!==Object.prototype && proto!==null) return null;
    const own=Reflect.ownKeys(raw);
    if (own.length<keys.length || own.length>keys.length+optional.length ||
        keys.some(key=>!own.includes(key)) ||
        own.some(key=>typeof key!=='string' ||
          !(keys.includes(key)||optional.includes(key)))) return null;
    const desc=Object.getOwnPropertyDescriptors(raw), out={};
    for (const key of [...keys,...optional.filter(key=>own.includes(key))]) {
      if (!desc[key] || !Object.hasOwn(desc[key],'value') ||
          desc[key].enumerable!==true) return null;
      Object.defineProperty(out,key,{value:desc[key].value,enumerable:true});
    }
    return Object.freeze(out);
  } catch (_) {return null;}
}
function safeHold(x) {
  return x && x.status==='SOURCE_ONLY_HOLD' &&
    x.authority==='LOCAL_UNAUTHENTICATED_OBSERVATION' &&
    x.liveness==='NOT_PROVEN' && x.automaticRestartAllowed===false &&
    x.activationAllowed===false && x.releaseAuthority==='NOT_ISSUED';
}
function validCase(raw) {
  const x=exact(raw,CASE_KEYS), c=exact(x?.counts,COUNT_KEYS);
  if (!safeHold(x) || x.schemaVersion!==1 ||
      x.kind!=='GUARDIAN_CASEWORK_DIAGNOSTICS_V1' ||
      x.result!=='LOCAL_STRUCTURE_OBSERVED_ONLY' ||
      x.reason!=='GUARDIAN_DIAG_LOCAL_STRUCTURE_OBSERVED' ||
      x.journalState!=='JOURNAL_STRUCTURALLY_CONSISTENT' ||
      x.lockState!=='LOCK_ABSENT_OBSERVED' ||
      !SHA.test(x.journalSha256??'') || x.custodyVerified!==false ||
      x.manualInterventionRequired!==true || !c ||
      COUNT_KEYS.some(k=>!Number.isSafeInteger(c[k]) || c[k]<0 || c[k]>4096) ||
      c.receipts!==c.quarantined+c.duplicates+c.rejected+c.handoffs ||
      c.returns>c.handoffs) return null;
  return Object.freeze({sha:x.journalSha256,counts:c});
}
function validRuntime(raw) {
  const x=exact(raw,RUNTIME_KEYS,['unterminatedGenerations']);
  if (!safeHold(x) || x.schemaVersion!==1 ||
      x.kind!=='GUARDIAN_LOCAL_RUNTIME_ASSESSMENT_V1' ||
      !PRIORITIES.has(x.priority) || x.priority==='P0' ||
      !STATES.has(x.processState) || !SHA.test(x.journalSha256??'') ||
      !Number.isSafeInteger(x.journalEntries) ||
      x.journalEntries<1 || x.journalEntries>4096 ||
      !Number.isSafeInteger(x.historicalFailureCount) ||
      x.historicalFailureCount<0 ||
      x.historicalFailureCount>x.journalEntries ||
      x.manualInterventionRequired!==(x.priority!=='P3') ||
      (Object.hasOwn(x,'unterminatedGenerations') &&
       (!Number.isSafeInteger(x.unterminatedGenerations) ||
        x.unterminatedGenerations<0 || x.unterminatedGenerations>4096)) ||
      (x.priority==='P3' &&
       (x.unterminatedGenerations>0 || x.historicalFailureCount>0 ||
        x.processState!=='STOPPED'))) return null;
  return Object.freeze({priority:x.priority,state:x.processState,
    sha:x.journalSha256,entries:x.journalEntries,
    failures:x.historicalFailureCount,
    generations:x.unterminatedGenerations??null});
}
function validEvent(raw) {
  const x=exact(raw,EVENT_KEYS);
  if (!x || !UUID.test(x.eventId??'') ||
      typeof x.timestamp!=='string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x.timestamp) ||
      !Number.isFinite(Date.parse(x.timestamp)) ||
      !['FAILED','STOPPED'].includes(x.state) ||
      (x.state==='STOPPED' && x.errorCode!==null) ||
      (x.state==='FAILED' && !CODE.test(x.errorCode??''))) return null;
  return x;
}
function validBrief(raw) {
  const x=exact(raw,BRIEF_KEYS);
  if (!safeHold(x) || x.schemaVersion!==1 ||
      x.kind!=='GUARDIAN_LOCAL_OPERATOR_INCIDENT_BRIEF_V1' ||
      x.classification!=='LOCAL_BRIEF_CONSISTENT' ||
      !['P1','P2','P3'].includes(x.priority) ||
      !STATES.has(x.processState) || !SHA.test(x.journalSha256??'') ||
      !Number.isSafeInteger(x.journalEntries) ||
      x.journalEntries<1 || x.journalEntries>4096 ||
      !Number.isSafeInteger(x.historicalFailureCount) ||
      x.historicalFailureCount<0 ||
      x.historicalFailureCount>x.journalEntries ||
      x.manualInterventionRequired!==true ||
      !Array.isArray(x.events) || x.events.length<1 || x.events.length>10 ||
      !SHA.test(x.briefSha256??'')) return null;
  const desc=Object.getOwnPropertyDescriptors(x.events);
  if (Reflect.ownKeys(x.events).length!==x.events.length+1 ||
      x.events.some((_,i)=>!desc[i] ||
        !Object.hasOwn(desc[i],'value') || !validEvent(desc[i].value))) return null;
  const original={};
  for(const key of BRIEF_KEYS.slice(0,-1)) original[key]=x[key];
  if (crypto.createHash('sha256').update(JSON.stringify(original))
    .digest('hex')!==x.briefSha256) return null;
  return Object.freeze({priority:x.priority,state:x.processState,
    sha:x.journalSha256,entries:x.journalEntries,
    failures:x.historicalFailureCount,briefSha:x.briefSha256,
    newest:validEvent(desc[0].value)});
}
function validAudit(raw) {
  const x=exact(raw,AUDIT_KEYS);
  if (!safeHold(x) || x.schemaVersion!==1 ||
      x.kind!=='GUARDIAN_LOCAL_EVENT_LEDGER_AUDIT_V1' ||
      x.comparison!=='MATCH_LOCAL_PAGES_ONLY' ||
      x.reason!=='GUARDIAN_LEDGER_COMPLETE_LOCAL' ||
      !STATES.has(x.processState) ||
      !SHA.test(x.journalSha256??'') ||
      !SHA.test(x.orderedEventsSha256??'') ||
      !Number.isSafeInteger(x.inspectedEntries) ||
      x.inspectedEntries<1 || x.inspectedEntries>4096 ||
      !Number.isSafeInteger(x.inspectedPages) ||
      x.inspectedPages<1 || x.inspectedPages>x.inspectedEntries ||
      !Number.isSafeInteger(x.failureCount) ||
      x.failureCount<0 || x.failureCount>x.inspectedEntries ||
      x.manualInterventionRequired!==true ||
      !Array.isArray(x.failureCodes) ||
      !validEvent(x.lastTerminal)) return null;
  return Object.freeze({state:x.processState,sha:x.journalSha256,
    entries:x.inspectedEntries,failures:x.failureCount,
    orderedSha:x.orderedEventsSha256,
    newest:validEvent(x.lastTerminal)});
}
function equal(a,b,fields) {
  return a&&b&&fields.every(k=>a[k]===b[k]);
}
function failure(reason) {
  return Object.freeze({
    schemaVersion:1,kind:'GUARDIAN_CASEWORK_GENERATION_ASSESSMENT_V1',
    authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    status:'SOURCE_ONLY_HOLD',classification:'NOT_VERIFIED',reason,
    priority:'P0',caseworkJournalSha256:null,terminalJournalSha256:null,
    orderedEventsSha256:null,caseworkCounts:null,
    terminalFailures:0,unterminatedGenerations:null,
    crossJournalBinding:'NOT_PROVEN',generationLedgerBinding:'NOT_PROVEN',
    custodyVerified:false,liveness:'NOT_PROVEN',
    manualInterventionRequired:true,automaticRestartAllowed:false,
    activationAllowed:false,releaseAuthority:'NOT_ISSUED',
  });
}
function createGuardianCaseworkGenerationAssessment(options) {
  const config=exact(options,['operator','caseworkDiagnostics']);
  if (!config || !config.operator || !config.caseworkDiagnostics ||
      typeof config.caseworkDiagnostics.inspect!=='function' ||
      ['assessRuntime','captureOfflineIncidentBrief',
        'auditCompleteEventLedger'].some(k=>typeof config.operator[k]!=='function')) {
    throw new Error('GUARDIAN_CASEWORK_GENERATION_CONFIG_INVALID');
  }
  function assess() {
    let c0,c1,r0,r1,brief,audit;
    try {
      // Casework A -> Generation runtime A -> terminal brief/audit ->
      // Generation runtime B -> Casework B. Neither service is locked.
      c0=validCase(config.caseworkDiagnostics.inspect());
      if (!c0) return failure('GUARDIAN_CASEWORK_SOURCE_UNVERIFIED');
      r0=validRuntime(config.operator.assessRuntime());
      if (!r0) return failure('GUARDIAN_GENERATION_SOURCE_UNVERIFIED');
      brief=validBrief(config.operator.captureOfflineIncidentBrief());
      audit=validAudit(config.operator.auditCompleteEventLedger());
      r1=validRuntime(config.operator.assessRuntime());
      c1=validCase(config.caseworkDiagnostics.inspect());
    } catch (_) {return failure('GUARDIAN_CORRELATION_READ_FAILED');}
    if (!c1 || !r1 || !brief || !audit ||
        !equal(c0,c1,['sha']) ||
        COUNT_KEYS.some(k=>c0.counts[k]!==c1.counts[k]) ||
        !equal(r0,r1,['priority','state','sha','entries','failures','generations']) ||
        !equal(r0,brief,['priority','state','sha','entries','failures']) ||
        !equal(r0,audit,['state','sha','entries','failures']) ||
        !equal(brief.newest,audit.newest,EVENT_KEYS)) {
      return failure('GUARDIAN_CORRELATION_SNAPSHOTS_CHANGED');
    }
    return Object.freeze({
      schemaVersion:1,kind:'GUARDIAN_CASEWORK_GENERATION_ASSESSMENT_V1',
      authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
      status:'SOURCE_ONLY_HOLD',
      classification:'LOCAL_COINCIDENT_OBSERVATIONS_ONLY',
      reason:'GUARDIAN_CASEWORK_GENERATION_LOCAL_SNAPSHOTS',
      priority:r1.priority,caseworkJournalSha256:c1.sha,
      terminalJournalSha256:audit.sha,
      orderedEventsSha256:audit.orderedSha,
      caseworkCounts:c1.counts,terminalFailures:audit.failures,
      unterminatedGenerations:r1.generations,
      crossJournalBinding:'NOT_PROVEN',
      generationLedgerBinding:'NOT_PROVEN',
      custodyVerified:false,liveness:'NOT_PROVEN',
      manualInterventionRequired:true,automaticRestartAllowed:false,
      activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    });
  }
  return Object.freeze({assess});
}
module.exports=Object.freeze({createGuardianCaseworkGenerationAssessment});
