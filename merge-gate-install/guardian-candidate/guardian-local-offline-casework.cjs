/**
 * G27E — offline, owner-only local intake casework.
 * Append-only batch idempotency, bounded exception query and manual handoff
 * ANNOTATIONS. Not a credential, human signature, attestation or HOLD release.
 * Import/construction are inert. Source-only isolated process; no live I/O.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { verifyBundle, verifyBundleHistory } =
  require('./guardian-local-offline-brief-verifier.cjs');
const { parseUniqueKeySourceLock } =
  require('../candidate/verify-source-lock.cjs');
const NAME = /^guardian-[a-z0-9-]{1,50}\.jsonl$/;
const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODES = /^GUARDIAN_[A-Z0-9_]{1,100}$/;
const FIELDS = Object.freeze(['schemaVersion','kind','id','timestamp','type',
  'decision','reason','bundleSha256','originalId','subjectId','transition']);
const OPTIONS = Object.freeze(['directory','fileName','maxJournalBytes']);
const MAX_LINES = 4096, MAX_INTAKE = 8, MAX_INPUT = 96_000;
const INTAKE_REASONS = new Set([
  'GUARDIAN_CASEWORK_QUARANTINED','GUARDIAN_CASEWORK_DUPLICATE',
  'GUARDIAN_CASEWORK_INPUT_INVALID','GUARDIAN_CASEWORK_BUNDLE_INVALID',
  'GUARDIAN_CASEWORK_HISTORY_INCOMPLETE','GUARDIAN_CASEWORK_HISTORY_CONFLICT',
  'GUARDIAN_CASEWORK_HISTORY_UNVERIFIED',
]);
const TRANSITIONS = Object.freeze({
  REQUESTED: 'GUARDIAN_CASEWORK_HANDOFF_REQUESTED',
  ACKNOWLEDGED: 'GUARDIAN_CASEWORK_HANDOFF_ACKNOWLEDGED',
  RETURNED: 'GUARDIAN_CASEWORK_HANDOFF_RETURNED',
});
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return null;
    const all = Reflect.ownKeys(value);
    if (all.length !== keys.length ||
        all.some(k => typeof k !== 'string' || !keys.includes(k))) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const clone = {};
    for (const k of keys) {
      if (!Object.hasOwn(descriptors[k], 'value') ||
          descriptors[k].enumerable !== true) return null;
      clone[k] = descriptors[k].value;
    }
    return Object.freeze(clone);
  } catch (_) { return null; }
}
function arraySnapshot(x, max) {
  try {
    if (!Array.isArray(x) || x.length < 1 || x.length > max) return null;
    const descriptors = Object.getOwnPropertyDescriptors(x);
    if (Reflect.ownKeys(x).length !== x.length + 1) return null;
    const output = [];
    for (let i=0; i<x.length; i++) {
      if (!Object.hasOwn(descriptors[i], 'value')) return null;
      output.push(descriptors[i].value);
    }
    return output;
  } catch (_) { return null; }
}
function receipt(type, decision, reason, digest = null, originalId = null,
  subjectId = null, transition = null) {
  return Object.freeze({
    schemaVersion: 1, kind: 'GUARDIAN_CASEWORK_RECEIPT_V1',
    id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    type, decision, reason, bundleSha256: digest, originalId,
    subjectId, transition,
  });
}
function validRecord(input) {
  const x = exact(input, FIELDS);
  if (!x || x.schemaVersion !== 1 || x.kind !== 'GUARDIAN_CASEWORK_RECEIPT_V1' ||
      typeof x.id !== 'string' || !UUID.test(x.id) ||
      typeof x.timestamp !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x.timestamp) ||
      !Number.isFinite(Date.parse(x.timestamp)) ||
      !(x.bundleSha256 === null || (typeof x.bundleSha256 === 'string' && HEX.test(x.bundleSha256))) ||
      !(x.originalId === null || (typeof x.originalId === 'string' && UUID.test(x.originalId))) ||
      !(x.subjectId === null || (typeof x.subjectId === 'string' && UUID.test(x.subjectId)))) return null;
  if (x.type === 'INTAKE') {
    if (!['QUARANTINED','DUPLICATE','REJECTED'].includes(x.decision) ||
        !INTAKE_REASONS.has(x.reason) ||
        x.subjectId !== null || x.transition !== null ||
        (x.decision === 'QUARANTINED' &&
          (x.reason !== 'GUARDIAN_CASEWORK_QUARANTINED' ||
           x.bundleSha256 === null || x.originalId !== null)) ||
        (x.decision === 'DUPLICATE' &&
          (x.reason !== 'GUARDIAN_CASEWORK_DUPLICATE' ||
           x.bundleSha256 === null || x.originalId === null)) ||
        (x.decision === 'REJECTED' && (x.originalId !== null ||
           x.reason === 'GUARDIAN_CASEWORK_QUARANTINED' ||
           x.reason === 'GUARDIAN_CASEWORK_DUPLICATE'))) return null;
  } else if (x.type === 'HANDOFF') {
    if (x.decision !== null || x.originalId !== null ||
        x.bundleSha256 !== null || x.subjectId === null ||
        typeof x.transition !== 'string' ||
        !Object.hasOwn(TRANSITIONS, x.transition) ||
        TRANSITIONS[x.transition] !== x.reason) return null;
  } else return null;
  return x;
}
function fail(reason = 'GUARDIAN_CASEWORK_EVIDENCE_UNVERIFIED') {
  return Object.freeze({
    status:'SOURCE_ONLY_HOLD', authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    decision:'NOT_VERIFIED', reason,
    journalSha256:null, entries:Object.freeze([]), nextCursor:null,
    custodyVerified:false,
    manualInterventionRequired:true, liveness:'NOT_PROVEN',
    automaticRestartAllowed:false, activationAllowed:false,
    releaseAuthority:'NOT_ISSUED',
  });
}
function result(reason, entries, sha, cursor = null) {
  return Object.freeze({
    status:'SOURCE_ONLY_HOLD', authority:'LOCAL_UNAUTHENTICATED_OBSERVATION',
    decision:'LOCAL_RECORD_ONLY', reason,
    journalSha256:sha, entries:Object.freeze(entries),
    nextCursor:cursor, custodyVerified:false,
    manualInterventionRequired:true,
    liveness:'NOT_PROVEN', automaticRestartAllowed:false,
    activationAllowed:false, releaseAuthority:'NOT_ISSUED',
  });
}
function classify(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_INPUT ||
      text.length === 0) {
    return {decision:'REJECTED',reason:'GUARDIAN_CASEWORK_INPUT_INVALID',sha:null};
  }
  try {
    parseUniqueKeySourceLock(Buffer.from(text,'utf8'));
  } catch (_) {
    return {decision:'REJECTED',reason:'GUARDIAN_CASEWORK_INPUT_INVALID',sha:null};
  }
  const bundle = verifyBundle(text);
  if (bundle.comparison !== 'MATCH_LOCAL_CHECKSUM_ONLY') {
    return {decision:'REJECTED',reason:'GUARDIAN_CASEWORK_BUNDLE_INVALID',sha:null};
  }
  const history = verifyBundleHistory(text);
  if (history.comparison === 'LOCAL_STRUCTURAL_OBSERVATION_ONLY' &&
      history.bundleSha256 === bundle.bundleSha256) {
    return {decision:'QUARANTINED',reason:'GUARDIAN_CASEWORK_QUARANTINED',
      sha:bundle.bundleSha256};
  }
  const mapped = {
    GUARDIAN_BRIEF_CONTINUITY_INCOMPLETE_HISTORY:
      'GUARDIAN_CASEWORK_HISTORY_INCOMPLETE',
    GUARDIAN_BRIEF_CONTINUITY_CONFLICT: 'GUARDIAN_CASEWORK_HISTORY_CONFLICT',
  };
  return {decision:'REJECTED',
    reason:mapped[history.reason] ?? 'GUARDIAN_CASEWORK_HISTORY_UNVERIFIED',
    sha:bundle.bundleSha256};
}
function validateTimeline(entries) {
  const ids = new Set(), first = new Map(), handoffs = new Map();
  for (const row of entries) {
    if (ids.has(row.id)) return false;
    ids.add(row.id);
    if (row.type === 'INTAKE') {
      if (row.decision === 'QUARANTINED') {
        if (first.has(row.bundleSha256)) return false;
        first.set(row.bundleSha256,row.id);
      } else if (row.decision === 'DUPLICATE' &&
          first.get(row.bundleSha256) !== row.originalId) return false;
    } else {
      const origin = entries.find(x => x.id === row.subjectId &&
        x.type === 'INTAKE' && x.decision === 'QUARANTINED');
      if (!origin || !ids.has(origin.id)) return false;
      const prev = handoffs.get(row.subjectId) ?? null;
      if (!((row.transition === 'REQUESTED' &&
              (prev === null || prev === 'RETURNED')) ||
            (row.transition === 'ACKNOWLEDGED' && prev === 'REQUESTED') ||
            (row.transition === 'RETURNED' &&
              ['REQUESTED','ACKNOWLEDGED'].includes(prev)))) return false;
      handoffs.set(row.subjectId,row.transition);
    }
  }
  return {first,handoffs};
}

function createGuardianOfflineCasework(options) {
  let config;
  try { config = exact(options, Reflect.ownKeys(options)); }
  catch (_) { config = null; }
  if (!config || Reflect.ownKeys(config).some(k => !OPTIONS.includes(k)) ||
      typeof config.directory !== 'string' ||
      !path.isAbsolute(config.directory) ||
      typeof config.fileName !== 'string' || !NAME.test(config.fileName)) {
    throw new Error('GUARDIAN_CASEWORK_CONFIG_INVALID');
  }
  const max = config.maxJournalBytes ?? 1_048_576;
  if (!Number.isSafeInteger(max) || max < 1024 || max > 10_485_760) {
    throw new Error('GUARDIAN_CASEWORK_CONFIG_INVALID');
  }
  let directory, anchor;
  try {
    directory = fs.realpathSync(config.directory);
    anchor = fs.statSync(directory);
    if (!anchor.isDirectory() || (anchor.mode & 0o077) !== 0 ||
        (typeof process.getuid === 'function' && anchor.uid !== process.getuid())) {
      throw new Error('unsafe');
    }
  } catch (_) { throw new Error('GUARDIAN_CASEWORK_DIRECTORY_UNVERIFIED'); }
  const file = path.join(directory,config.fileName);
  const lockFile = file + '.lock';
  const fdflags = fs.constants.O_RDWR | fs.constants.O_APPEND |
    (fs.constants.O_NOFOLLOW ?? 0);
  // A single owner-held writer retains a volatile high-watermark after its
  // first trusted read. A new process has no historical custody proof.
  let witness = null, witnessBroken = false;
  const META = ['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'];
  function sameMetadata(a,b) {
    return META.every(k => a[k] === b[k]);
  }
  function makeWitness(state) {
    return Object.freeze({
      dev:state.identity.dev, ino:state.identity.ino,
      size:state.identity.size, sha:state.sha,
      mtimeMs:state.identity.mtimeMs, ctimeMs:state.identity.ctimeMs,
    });
  }
  function matchesWitness(state,old) {
    return state.identity.dev === old.dev && state.identity.ino === old.ino &&
      state.identity.size === old.size && state.sha === old.sha &&
      state.identity.mtimeMs === old.mtimeMs &&
      state.identity.ctimeMs === old.ctimeMs;
  }
  function trustedDir() {
    try {
      const st=fs.statSync(directory);
      return st.isDirectory() && st.dev===anchor.dev &&
        st.ino===anchor.ino && (st.mode & 0o077)===0 &&
        fs.realpathSync(config.directory)===directory &&
        (typeof process.getuid!=='function' || st.uid===process.getuid());
    } catch (_) {return false;}
  }
  function snapshot(fd) {
    const a=fs.fstatSync(fd), pathname=fs.lstatSync(file);
    if (!a.isFile() || a.nlink!==1 || (a.mode & 0o077)!==0 ||
        a.size>max || pathname.isSymbolicLink() ||
        !pathname.isFile() || !sameMetadata(a,pathname) ||
        (typeof process.getuid==='function' && a.uid!==process.getuid())) {
      throw new Error('unsafe journal');
    }
    const buf=Buffer.alloc(a.size);
    let at=0;
    while (at<buf.length) {
      const n=fs.readSync(fd,buf,at,buf.length-at,at);
      if (n<=0) throw new Error('short read');
      at+=n;
    }
    const b=fs.fstatSync(fd), endPath=fs.lstatSync(file);
    if (!sameMetadata(a,b) || !sameMetadata(a,endPath) ||
        !endPath.isFile() || endPath.isSymbolicLink()) {
      throw new Error('unstable journal');
    }
    let rows=[];
    if (buf.length) {
      if (buf[buf.length-1]!==10 ||
          !Buffer.from(buf.toString('utf8'),'utf8').equals(buf)) {
        throw new Error('invalid journal bytes');
      }
      const lines=buf.toString('utf8').slice(0,-1).split('\n');
      if (lines.length>MAX_LINES) throw new Error('oversize journal');
      rows=lines.map(line=>{
        if (Buffer.byteLength(line,'utf8')>512) {
          throw new Error('oversize record');
        }
        const parsed=validRecord(parseUniqueKeySourceLock(Buffer.from(line)));
        if (!parsed) throw new Error('invalid record');
        return parsed;
      });
      if (!validateTimeline(rows)) throw new Error('invalid timeline');
    }
    return {rows,bytes:buf,identity:a,
      sha:buf.length?crypto.createHash('sha256').update(buf).digest('hex'):null};
  }
  function withExclusive(action) {
    if (witnessBroken || !trustedDir()) return fail();
    let guard,fd,obtained=false,identity=null;
    const writer = {started:false,verified:false};
    try {
      guard=fs.openSync(lockFile,fs.constants.O_CREAT|fs.constants.O_EXCL|
        fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW??0),0o600);
      obtained=true;
      identity=fs.fstatSync(guard);
      fs.closeSync(guard);guard=undefined;
      // After a witnessed file has existed, NEVER re-create it after
      // deletion. Omitting O_CREAT prevents producing a false new baseline.
      fd=fs.openSync(file,fdflags | (witness===null?fs.constants.O_CREAT:0),0o600);
      const state=snapshot(fd);
      if (witness && !matchesWitness(state,witness)) {
        witnessBroken=true;
        return fail();
      }
      if (!witness) witness=makeWitness(state);
      return action(state,fd,writer);
    } catch (_) {
      // Once witnessed, even an uncertain failed read/write requires Owner
      // intervention; a later restoration must not heal this session.
      if (witness) witnessBroken=true;
      return fail();
    } finally {
      if (fd!==undefined) {try {fs.closeSync(fd);}catch (_) {}}
      if (guard!==undefined) {try {fs.closeSync(guard);}catch (_) {}}
      // An uncertain write retains its lock for manual investigation.
      if (obtained && (!writer.started || writer.verified)) {
        try {
          const now=fs.lstatSync(lockFile);
          if (now.isFile() && !now.isSymbolicLink() &&
              now.dev===identity.dev && now.ino===identity.ino) {
            fs.unlinkSync(lockFile);
          }
        } catch (_) {}
      }
    }
  }
  function append(fd, before, newRows, writer) {
    if (before.rows.length+newRows.length>MAX_LINES) {
      throw new Error('record cap');
    }
    const data=Buffer.from(newRows.map(x=>JSON.stringify(x)+'\n').join(''));
    if (before.bytes.length+data.length>max) throw new Error('journal cap');
    // Reopen neither the journal nor the lock: operate only on the
    // protected descriptor, but detect a mutation since the earlier read.
    const now=snapshot(fd);
    if (!matchesWitness(now,makeWitness(before)) ||
        !now.bytes.equals(before.bytes) || !trustedDir()) {
      witnessBroken=true;
      throw new Error('journal changed before append');
    }
    writer.started=true;
    if (fs.writeSync(fd,data,0,data.length)!==data.length) {
      throw new Error('partial write');
    }
    fs.fsyncSync(fd);
    const after=snapshot(fd), expected=Buffer.concat([before.bytes,data]);
    if (after.identity.dev!==before.identity.dev ||
        after.identity.ino!==before.identity.ino ||
        !after.bytes.equals(expected) || !trustedDir()) {
      throw new Error('journal changed after append');
    }
    witness=makeWitness(after);
    writer.verified=true;
  }
  function intakeMany(raw) {
    const batch=arraySnapshot(raw,MAX_INTAKE);
    if (!batch) return fail('GUARDIAN_CASEWORK_BATCH_INVALID');
    return withExclusive((state,fd,writer)=>{
      const {rows}=state;
      const timeline=validateTimeline(rows);
      if (!timeline) return fail();
      const first=new Map(timeline.first), added=[];
      for (const input of batch) {
        const parsed=classify(input);
        let decision=parsed.decision,reason=parsed.reason,originalId=null;
        if (parsed.sha && first.has(parsed.sha)) {
          decision='DUPLICATE';reason='GUARDIAN_CASEWORK_DUPLICATE';
          originalId=first.get(parsed.sha);
        }
        const entry=receipt('INTAKE',decision,reason,parsed.sha,originalId);
        added.push(entry);
        if (decision==='QUARANTINED') first.set(parsed.sha,entry.id);
      }
      if (!validateTimeline([...rows,...added])) return fail();
      append(fd,state,added,writer);
      const items=added.map(x=>Object.freeze({
        id:x.id,decision:x.decision,reason:x.reason,
        bundleSha256:x.bundleSha256,originalId:x.originalId,
      }));
      return result('GUARDIAN_CASEWORK_BATCH_RECORDED',items,null);
    });
  }
  function handoff(options) {
    const request=exact(options,['receiptId','transition']);
    if (!request || typeof request.receiptId!=='string' ||
        !UUID.test(request.receiptId) ||
        typeof request.transition!=='string' ||
        !Object.hasOwn(TRANSITIONS,request.transition)) {
      return fail('GUARDIAN_CASEWORK_HANDOFF_INVALID');
    }
    return withExclusive((state,fd,writer)=>{
      const {rows}=state;
      const origin=rows.find(x=>x.id===request.receiptId &&
        x.type==='INTAKE' && x.decision==='QUARANTINED');
      if (!origin) return fail('GUARDIAN_CASEWORK_HANDOFF_INVALID');
      const previous=rows.filter(x=>x.type==='HANDOFF' &&
        x.subjectId===origin.id).at(-1)?.transition ?? null;
      if (!((request.transition==='REQUESTED' &&
            (previous===null||previous==='RETURNED')) ||
        (request.transition==='ACKNOWLEDGED'&&previous==='REQUESTED') ||
        (request.transition==='RETURNED'&&
          ['REQUESTED','ACKNOWLEDGED'].includes(previous)))) {
        return fail('GUARDIAN_CASEWORK_HANDOFF_TRANSITION_INVALID');
      }
      const entry=receipt('HANDOFF',null,TRANSITIONS[request.transition],
        null,null,origin.id,request.transition);
      if (!validateTimeline([...rows,entry])) return fail();
      append(fd,state,[entry],writer);
      return result('GUARDIAN_CASEWORK_HANDOFF_ANNOTATED',
        [Object.freeze({id:entry.id,subjectId:origin.id,
          transition:entry.transition,reason:entry.reason})],null);
    });
  }
  function exceptions(params={}) {
    let config;
    try { config=exact(params,Reflect.ownKeys(params)); }
    catch (_) { config=null; }
    if (!config || Reflect.ownKeys(config).some(k=>!['limit','cursor'].includes(k))) {
      return fail('GUARDIAN_CASEWORK_QUERY_INVALID');
    }
    const limit=config.limit??10;
    if (!Number.isSafeInteger(limit)||limit<1||limit>20) {
      return fail('GUARDIAN_CASEWORK_QUERY_INVALID');
    }
    const cur=config.cursor===undefined?null:exact(config.cursor,['sha','before']);
    if (config.cursor!==undefined && cur===null ||
        cur && (typeof cur.sha!=='string'||!HEX.test(cur.sha)||
          !Number.isSafeInteger(cur.before)||cur.before<1||
          cur.before>MAX_LINES)) return fail('GUARDIAN_CASEWORK_QUERY_INVALID');
    if (witnessBroken || !trustedDir()) return fail();
    let fd;
    try {
      fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW??0));
      const state=snapshot(fd), {rows,sha}=state;
      if (witness && !matchesWitness(state,witness)) {
        witnessBroken=true;
        return fail();
      }
      if (!witness) witness=makeWitness(state);
      if (cur && (cur.sha!==sha||cur.before>rows.length)) {
        return fail('GUARDIAN_CASEWORK_CURSOR_STALE');
      }
      const end=cur?.before??rows.length, items=[];
      let index=end-1;
      while (index>=0 && items.length<limit) {
        const row=rows[index];
        if ((row.type==='INTAKE'&&row.decision!=='QUARANTINED') ||
            (row.type==='HANDOFF'&&row.transition==='RETURNED')) {
          items.push(Object.freeze({
            id:row.id,type:row.type,decision:row.decision,
            reason:row.reason,originalId:row.originalId,
            subjectId:row.subjectId,transition:row.transition,
          }));
        }
        index--;
      }
      const next=index>=0&&items.length===limit ?
        Object.freeze({sha,before:index+1}):null;
      return result('GUARDIAN_CASEWORK_EXCEPTIONS_LOCAL_ONLY',
        items,sha,next);
    } catch (err) {
      if (witness) witnessBroken=true;
      if (err?.code==='ENOENT' && !cur && !witness) {
        return result('GUARDIAN_CASEWORK_EXCEPTIONS_NO_JOURNAL',[],null);
      }
      return fail();
    } finally {if(fd!==undefined){try{fs.closeSync(fd);}catch(_){}}}
  }
  return Object.freeze({intakeMany,handoff,exceptions});
}
module.exports={createGuardianOfflineCasework};
