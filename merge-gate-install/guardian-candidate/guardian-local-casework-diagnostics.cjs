/**
 * Guardian G27F: passive local intake journal + unknown lock diagnostics.
 * Reads only. No lock acquisition, release, unlink, file creation,
 * process signalling, startup, recovery or publication.
 *
 * A present lock is NEVER classified as stale/safe to delete from metadata.
 * A clean local receipt list is not authenticated/immutable evidence.
 */
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');

const CONFIG = Object.freeze(['directory', 'fileName', 'maxJournalBytes']);
const RECORD = Object.freeze(['schemaVersion','kind','id','timestamp','type',
  'decision','reason','bundleSha256','originalId','subjectId','transition']);
const NAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const SHA = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const INPUT_REASONS = new Set([
  'GUARDIAN_CASEWORK_QUARANTINED','GUARDIAN_CASEWORK_DUPLICATE',
  'GUARDIAN_CASEWORK_INPUT_INVALID','GUARDIAN_CASEWORK_BUNDLE_INVALID',
  'GUARDIAN_CASEWORK_HISTORY_INCOMPLETE','GUARDIAN_CASEWORK_HISTORY_CONFLICT',
  'GUARDIAN_CASEWORK_HISTORY_UNVERIFIED',
]);
const HANDOFF = Object.freeze({
  REQUESTED:'GUARDIAN_CASEWORK_HANDOFF_REQUESTED',
  ACKNOWLEDGED:'GUARDIAN_CASEWORK_HANDOFF_ACKNOWLEDGED',
  RETURNED:'GUARDIAN_CASEWORK_HANDOFF_RETURNED',
});
const MAX_LINES = 4096;
const MAX_LINE_BYTES = 512;
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const own = Reflect.ownKeys(value);
    if (own.length !== keys.length ||
        own.some(k => typeof k !== 'string' || !keys.includes(k))) return null;
    const desc = Object.getOwnPropertyDescriptors(value), result = {};
    for (const k of keys) {
      if (!desc[k] || !Object.hasOwn(desc[k], 'value') ||
          desc[k].enumerable !== true) return null;
      result[k] = desc[k].value;
    }
    return Object.freeze(result);
  } catch (_) { return null; }
}
function isUUID(x) {return typeof x === 'string' && UUID.test(x);}
function isSha(x) {return typeof x === 'string' && SHA.test(x);}
function validTime(value) {
  if (typeof value !== 'string' || !UTC.test(value)) return false;
  try {return new Date(value).toISOString() === value;}
  catch (_) {return false;}
}
function validRow(value) {
  const r = exact(value, RECORD);
  if (!r || r.schemaVersion !== 1 ||
      r.kind !== 'GUARDIAN_CASEWORK_RECEIPT_V1' ||
      !isUUID(r.id) || !validTime(r.timestamp) ||
      !(r.bundleSha256 === null || isSha(r.bundleSha256)) ||
      !(r.originalId === null || isUUID(r.originalId)) ||
      !(r.subjectId === null || isUUID(r.subjectId))) return null;
  if (r.type === 'INTAKE') {
    if (!['QUARANTINED','DUPLICATE','REJECTED'].includes(r.decision) ||
        !INPUT_REASONS.has(r.reason) || r.subjectId !== null ||
        r.transition !== null) return null;
    if (r.decision === 'QUARANTINED' &&
        (r.reason !== 'GUARDIAN_CASEWORK_QUARANTINED' ||
         !isSha(r.bundleSha256) || r.originalId !== null)) return null;
    if (r.decision === 'DUPLICATE' &&
        (r.reason !== 'GUARDIAN_CASEWORK_DUPLICATE' ||
         !isSha(r.bundleSha256) || !isUUID(r.originalId))) return null;
    if (r.decision === 'REJECTED' &&
        (r.originalId !== null ||
         ['GUARDIAN_CASEWORK_QUARANTINED','GUARDIAN_CASEWORK_DUPLICATE']
           .includes(r.reason) ||
         (r.reason === 'GUARDIAN_CASEWORK_INPUT_INVALID' &&
          r.bundleSha256 !== null) ||
         (r.reason === 'GUARDIAN_CASEWORK_BUNDLE_INVALID' &&
          r.bundleSha256 !== null))) return null;
  } else if (r.type === 'HANDOFF') {
    if (r.decision !== null || r.originalId !== null ||
        r.bundleSha256 !== null || !isUUID(r.subjectId) ||
        !Object.hasOwn(HANDOFF, r.transition) ||
        HANDOFF[r.transition] !== r.reason) return null;
  } else return null;
  return r;
}
function summarise(rows) {
  const ids = new Set(), first = new Map(), ownerIds = new Set(),
    previous = new Map();
  const stats = {receipts:rows.length, quarantined:0, duplicates:0,
    rejected:0, handoffs:0, returns:0};
  for (const r of rows) {
    if (ids.has(r.id)) return null;
    ids.add(r.id);
    if (r.type === 'INTAKE') {
      if (r.decision === 'QUARANTINED') {
        if (first.has(r.bundleSha256)) return null;
        first.set(r.bundleSha256,r.id);
        ownerIds.add(r.id);
        stats.quarantined++;
      } else if (r.decision === 'DUPLICATE') {
        if (first.get(r.bundleSha256) !== r.originalId) return null;
        stats.duplicates++;
      } else stats.rejected++;
    } else {
      // The referenced intake must already have been recorded. A later
      // receipt cannot retroactively justify an earlier handoff.
      if (!ownerIds.has(r.subjectId)) {
        return null;
      }
      const prior = previous.get(r.subjectId) ?? null;
      if (!((r.transition === 'REQUESTED' &&
             (prior === null || prior === 'RETURNED')) ||
            (r.transition === 'ACKNOWLEDGED' && prior === 'REQUESTED') ||
            (r.transition === 'RETURNED' &&
             ['REQUESTED','ACKNOWLEDGED'].includes(prior)))) return null;
      previous.set(r.subjectId,r.transition);
      stats.handoffs++;
      if (r.transition === 'RETURNED') stats.returns++;
    }
  }
  return Object.freeze(stats);
}
function metadata(st) {
  return Object.freeze({
    dev:st.dev,ino:st.ino,size:st.size,mtimeMs:st.mtimeMs,
    ctimeMs:st.ctimeMs,mode:st.mode,nlink:st.nlink,
  });
}
function sameMeta(a,b) {
  if (a === null || b === null) return a === null && b === null;
  return Object.keys(a).every(k => a[k] === b[k]);
}
function safeFile(st) {
  return st.isFile() && !st.isSymbolicLink() && st.nlink === 1 &&
    (st.mode & 0o077) === 0 &&
    (typeof process.getuid !== 'function' || st.uid === process.getuid());
}
function lockSnapshot(file) {
  try {
    const st=fs.lstatSync(file);
    if (!safeFile(st)) return {state:'LOCK_UNSAFE',stamp:null};
    // Do NOT read contents, expose PID, inspect age or infer ownership.
    return {state:'LOCK_PRESENT_UNVERIFIED',stamp:metadata(st)};
  } catch (e) {
    return e?.code === 'ENOENT' ?
      {state:'LOCK_ABSENT_OBSERVED',stamp:null} :
      {state:'LOCK_UNVERIFIED',stamp:null};
  }
}
function openJournal(file,max) {
  let fd;
  try {
    fd=fs.openSync(file,fs.constants.O_RDONLY |
      (fs.constants.O_NOFOLLOW ?? 0));
    const begin=fs.fstatSync(fd);
    if (!safeFile(begin) || begin.size > max || begin.size < 1) {
      return {state:'JOURNAL_UNVERIFIED',stats:null,digest:null};
    }
    const contents=Buffer.alloc(begin.size);
    let read=0;
    while(read<contents.length) {
      const bytes=fs.readSync(fd,contents,read,contents.length-read,read);
      if (!Number.isSafeInteger(bytes) || bytes<1) {
        throw new Error('incomplete snapshot');
      }
      read+=bytes;
    }
    const end=fs.fstatSync(fd);
    const pathMeta=fs.lstatSync(file);
    if (!sameMeta(metadata(begin),metadata(end)) ||
        !sameMeta(metadata(begin),metadata(pathMeta)) ||
        !pathMeta.isFile() || pathMeta.isSymbolicLink()) {
      return {state:'JOURNAL_CHANGED_DURING_READ',stats:null,digest:null};
    }
    if (contents.at(-1)!==10 ||
        !Buffer.from(contents.toString('utf8'),'utf8').equals(contents)) {
      return {state:'JOURNAL_INVALID',stats:null,digest:null};
    }
    const lines=contents.toString('utf8').slice(0,-1).split('\n');
    if (lines.length>MAX_LINES) return {state:'JOURNAL_INVALID',stats:null,digest:null};
    const rows=[];
    for (const line of lines) {
      if (!line || Buffer.byteLength(line,'utf8')>MAX_LINE_BYTES) {
        return {state:'JOURNAL_INVALID',stats:null,digest:null};
      }
      let row;
      try {row=validRow(parseUniqueKeySourceLock(Buffer.from(line,'utf8')));}
      catch (_) {return {state:'JOURNAL_INVALID',stats:null,digest:null};}
      if (!row) return {state:'JOURNAL_INVALID',stats:null,digest:null};
      rows.push(row);
    }
    const stats=summarise(rows);
    if (!stats) return {state:'JOURNAL_INVALID',stats:null,digest:null};
    return {state:'JOURNAL_STRUCTURALLY_CONSISTENT',
      stats,rows:Object.freeze(rows),stamp:metadata(begin),
      digest:crypto.createHash('sha256').update(contents).digest('hex')};
  } catch (e) {
    return e?.code === 'ENOENT' ?
      {state:'JOURNAL_MISSING',stats:null,digest:null} :
      {state:'JOURNAL_UNVERIFIED',stats:null,digest:null};
  } finally {
    if (fd!==undefined) {try {fs.closeSync(fd);}catch(_) {}}
  }
}
function failure(reason,journalState='UNVERIFIED',lockState='LOCK_UNVERIFIED') {
  return Object.freeze({
    schemaVersion:1,kind:'GUARDIAN_CASEWORK_DIAGNOSTICS_V1',
    status:'SOURCE_ONLY_HOLD',
    authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    result:'NOT_VERIFIED',reason,journalState,lockState,
    journalSha256:null,counts:null,
    liveness:'NOT_PROVEN',custodyVerified:false,
    manualInterventionRequired:true,
    automaticRestartAllowed:false,activationAllowed:false,
    releaseAuthority:'NOT_ISSUED',
  });
}
function observation(journal,lock) {
  const usable=journal.state==='JOURNAL_STRUCTURALLY_CONSISTENT';
  const unlocked=lock.state==='LOCK_ABSENT_OBSERVED';
  const consistent=usable && unlocked;
  const reason=!usable?'GUARDIAN_DIAG_JOURNAL_UNVERIFIED' :
    !unlocked?'GUARDIAN_DIAG_LOCK_REQUIRES_OWNER_REVIEW' :
      'GUARDIAN_DIAG_LOCAL_STRUCTURE_OBSERVED';
  return Object.freeze({
    schemaVersion:1,kind:'GUARDIAN_CASEWORK_DIAGNOSTICS_V1',
    status:'SOURCE_ONLY_HOLD',
    authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    result:consistent?'LOCAL_STRUCTURE_OBSERVED_ONLY':'NOT_VERIFIED',
    reason,journalState:journal.state,lockState:lock.state,
    journalSha256:usable?journal.digest:null,
    counts:usable?journal.stats:null,
    liveness:'NOT_PROVEN',custodyVerified:false,
    manualInterventionRequired:true,
    automaticRestartAllowed:false,activationAllowed:false,
    releaseAuthority:'NOT_ISSUED',
  });
}
function createGuardianCaseworkDiagnostics(options) {
  let config;
  try {config=exact(options,Reflect.ownKeys(options??{}));}
  catch (_) {config=null;}
  if (!config || Reflect.ownKeys(config).some(k=>!CONFIG.includes(k)) ||
      typeof config.directory!=='string' ||
      !path.isAbsolute(config.directory) ||
      typeof config.fileName!=='string' || !NAME.test(config.fileName)) {
    throw new Error('GUARDIAN_CASEWORK_DIAGNOSTICS_CONFIG_INVALID');
  }
  const max=config.maxJournalBytes??1_048_576;
  if (!Number.isSafeInteger(max) || max<1024 || max>10_485_760) {
    throw new Error('GUARDIAN_CASEWORK_DIAGNOSTICS_CONFIG_INVALID');
  }
  let directory,anchor;
  try {
    directory=fs.realpathSync(config.directory);
    anchor=fs.statSync(directory);
    if (!anchor.isDirectory() || (anchor.mode&0o077)!==0 ||
        (typeof process.getuid==='function' && anchor.uid!==process.getuid())) {
      throw new Error('unsafe');
    }
  } catch (_) {throw new Error('GUARDIAN_CASEWORK_DIAGNOSTICS_DIRECTORY_UNVERIFIED');}
  const journal=path.join(directory,config.fileName);
  const lock=journal+'.lock';
  function trustedDirectory() {
    try {
      const st=fs.statSync(directory);
      return st.isDirectory() && st.dev===anchor.dev &&
        st.ino===anchor.ino && (st.mode&0o077)===0 &&
        (typeof process.getuid!=='function' || st.uid===process.getuid()) &&
        fs.realpathSync(config.directory)===directory;
    } catch (_) {return false;}
  }
  function inspect() {
    if (!trustedDirectory()) {
      return failure('GUARDIAN_DIAG_DIRECTORY_UNVERIFIED');
    }
    const lockBefore=lockSnapshot(lock);
    const journalState=openJournal(journal,max);
    // Read the protected journal again *after* the lock observation.
    // A writer replacing/rewriting the file during another local read
    // cannot pass with a single earlier clean journal snapshot.
    const journalAfter=openJournal(journal,max);
    const lockAfter=lockSnapshot(lock);
    if (journalState.state!==journalAfter.state ||
        journalState.digest!==journalAfter.digest ||
        (journalState.state==='JOURNAL_STRUCTURALLY_CONSISTENT' &&
         !sameMeta(journalState.stamp,journalAfter.stamp)) ||
        lockBefore.state!==lockAfter.state ||
        !sameMeta(lockBefore.stamp,lockAfter.stamp) ||
        !trustedDirectory()) {
      return failure('GUARDIAN_DIAG_CHANGED_DURING_READ',
        journalState.state,'LOCK_UNVERIFIED');
    }
    return observation(journalState,lockAfter);
  }
  // G41: only a nominated, previously quarantined receipt may be observed.
  // This does not resolve a bundle, authorize the claimed association with a
  // Generation, or grant custody. Double-check locks, journal bytes and inode.
  function inspectQuarantinedReceipt(input) {
    const request=exact(input,['receiptId','journalSha256']);
    const unavailable=(reason)=>Object.freeze({
      schemaVersion:2,kind:'GUARDIAN_CASEWORK_RECEIPT_OBSERVATION_V2',
      status:'SOURCE_ONLY_HOLD',
      authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
      result:'NOT_VERIFIED',reason,caseworkReceiptId:null,
      bundleSha256:null,journalSha256:null,
      custodyVerified:false,liveness:'NOT_PROVEN',
      manualInterventionRequired:true,automaticRestartAllowed:false,
      activationAllowed:false,releaseAuthority:'NOT_ISSUED',
    });
    if (!request || !isUUID(request.receiptId) ||
        !isSha(request.journalSha256)) {
      return unavailable('GUARDIAN_CASEWORK_PIN_INVALID');
    }
    try {
      if (!trustedDirectory()) {
        return unavailable('GUARDIAN_CASEWORK_PIN_SOURCE_UNVERIFIED');
      }
      const l0=lockSnapshot(lock);
      const a=openJournal(journal,max);
      const b=openJournal(journal,max);
      const l1=lockSnapshot(lock);
      if (!trustedDirectory() ||
          l0.state!=='LOCK_ABSENT_OBSERVED' ||
          l1.state!=='LOCK_ABSENT_OBSERVED' ||
          a.state!=='JOURNAL_STRUCTURALLY_CONSISTENT' ||
          b.state!=='JOURNAL_STRUCTURALLY_CONSISTENT' ||
          a.digest!==request.journalSha256 ||
          b.digest!==a.digest || !sameMeta(a.stamp,b.stamp)) {
        return unavailable('GUARDIAN_CASEWORK_PIN_SOURCE_UNVERIFIED');
      }
      const candidate=a.rows.find(row=>row.id===request.receiptId);
      const again=b.rows.find(row=>row.id===request.receiptId);
      if (!candidate || !again ||
          candidate.type!=='INTAKE' ||
          candidate.decision!=='QUARANTINED' ||
          candidate.reason!=='GUARDIAN_CASEWORK_QUARANTINED' ||
          !isSha(candidate.bundleSha256) ||
          candidate.bundleSha256!==again.bundleSha256 ||
          again.decision!=='QUARANTINED') {
        return unavailable('GUARDIAN_CASEWORK_PIN_NOT_QUARANTINED');
      }
      return Object.freeze({
        schemaVersion:2,kind:'GUARDIAN_CASEWORK_RECEIPT_OBSERVATION_V2',
        status:'SOURCE_ONLY_HOLD',
        authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
        result:'LOCAL_QUARANTINE_OBSERVED_ONLY',
        reason:'GUARDIAN_CASEWORK_PIN_LOCAL_RECORD_MATCH',
        caseworkReceiptId:candidate.id,
        bundleSha256:candidate.bundleSha256,
        journalSha256:a.digest,
        custodyVerified:false,liveness:'NOT_PROVEN',
        manualInterventionRequired:true,automaticRestartAllowed:false,
        activationAllowed:false,releaseAuthority:'NOT_ISSUED',
      });
    } catch (_) {
      return unavailable('GUARDIAN_CASEWORK_PIN_READ_FAILED');
    }
  }
  return Object.freeze({inspect,inspectQuarantinedReceipt});
}
module.exports={createGuardianCaseworkDiagnostics};
