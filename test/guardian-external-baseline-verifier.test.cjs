'use strict';
// G33: synthetic offline Ed25519 key fixture ONLY, never installed,
// persisted or provisioned as any production trust anchor or credential.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const { createGuardianExternalBaselineVerifier }=require(
  '../merge-gate-install/guardian-candidate/guardian-external-baseline-verifier.cjs');
const { createGuardianLocalReceiptJournal,generationLedgerName }=require(
  '../merge-gate-install/guardian-candidate/guardian-local-receipt-journal.cjs');

const FILE='guardian-g33-source-only.jsonl';
const PREFIX=Buffer.from('NOHANDS_GUARDIAN_EXTERNAL_BASELINE_V1\n');
const SCOPE='NOHANDS_GUARDIAN_GENERATION_PAIR_SOURCE_ONLY';
const KIND='GUARDIAN_EXTERNAL_GENERATION_BASELINE_V1';
const ID='synthetic-test-baseline-anchor';
function sha(x){return crypto.createHash('sha256').update(x).digest('hex');}
const signedKeys=['schemaVersion','kind','scope','anchorId','sequence',
  'observedAt','journalSha256','ledgerSha256','journalBytes','ledgerBytes',
  'algorithm'];
function syntheticSigner(){
  const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({type:'spki',format:'pem'});
  const pinnedSpkiSha256=sha(publicKey.export({type:'spki',format:'der'}));
  const sign=(body)=>{
    const data={};
    for(const key of signedKeys)data[key]=body[key];
    return crypto.sign(null,Buffer.concat([PREFIX,
      Buffer.from(JSON.stringify(data),'utf8')]),privateKey).toString('base64');
  };
  return {publicKeyPem,pinnedSpkiSha256,sign};
}
async function workspace(fn){
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-g33-'));
  try{
    const writer=createGuardianLocalReceiptJournal({directory,fileName:FILE});
    const journal=path.join(fs.realpathSync(directory),FILE);
    const ledger=path.join(fs.realpathSync(directory),generationLedgerName(FILE));
    const keys=syntheticSigner();
    const make=(overrides={})=>createGuardianExternalBaselineVerifier({
      directory,fileName:FILE,expectedAnchorId:ID,
      publicKeyPem:keys.publicKeyPem,
      pinnedSpkiSha256:keys.pinnedSpkiSha256,...overrides,
    });
    const append=(state='FAILED')=>{
      const generationId=crypto.randomBytes(16).toString('hex');
      writer.recordLaunch({generationId,activationAllowed:false,
        releaseAuthority:'NOT_ISSUED'});
      writer.append({state,generationId,errorCode:state==='FAILED'?
        'GUARDIAN_CHILD_EXIT_UNVERIFIED':null,
        hostStopped:state==='STOPPED',activationAllowed:false,
        automaticRestartAllowed:false,releaseAuthority:'NOT_ISSUED'});
    };
    const signPacket=(changes={})=>{
      const body={
        schemaVersion:1,kind:KIND,scope:SCOPE,anchorId:ID,sequence:1,
        observedAt:'2026-10-27T07:00:00.000Z',
        journalSha256:sha(fs.readFileSync(journal)),
        ledgerSha256:sha(fs.readFileSync(ledger)),
        journalBytes:fs.statSync(journal).size,
        ledgerBytes:fs.statSync(ledger).size,
        algorithm:'Ed25519',...changes,
      };
      return {...body,signatureBase64:keys.sign(body)};
    };
    await fn({directory,writer,journal,ledger,keys,make,append,signPacket});
  }finally {fs.rmSync(directory,{recursive:true,force:true});}
}
function hold(x){
  assert.equal(x.schemaVersion,1);
  assert.equal(x.kind,'GUARDIAN_EXTERNAL_BASELINE_COMPARISON_V1');
  assert.equal(x.status,'SOURCE_ONLY_HOLD');
  assert.equal(x.authority,'OWNER_PINNED_PUBLIC_KEY_UNATTESTED');
  assert.equal(x.externalAnchorVerified,false);
  assert.equal(x.historicalCompletenessVerified,false);
  assert.equal(x.custodyVerified,false);
  assert.equal(x.liveness,'NOT_PROVEN');
  assert.equal(x.manualInterventionRequired,true);
  assert.equal(x.automaticRestartAllowed,false);
  assert.equal(x.activationAllowed,false);
  assert.equal(x.releaseAuthority,'NOT_ISSUED');
  assert.ok(Object.isFrozen(x));
  for(const prop of ['token','privateKey','signedEnvelope','rawJournal',
    'trustAnchor','approve','issueCheck','restart','clearHold','pid']){
    assert.equal(Object.hasOwn(x,prop),false);
  }
}
function deny(x,code){
  hold(x);
  assert.equal(x.comparison,'NOT_VERIFIED');
  assert.equal(x.reason,code);
  assert.equal(x.pinnedSignerSignatureValid,false);
  assert.equal(x.journalSha256,null);
  assert.equal(x.ledgerSha256,null);
  assert.equal(x.signedPayloadSha256,null);
  assert.equal(x.anchorSequence,0);
}
function valid(x,seq=1){
  hold(x);
  assert.equal(x.comparison,'LOCAL_SIGNATURE_AND_PAIR_MATCH_ONLY');
  assert.equal(x.reason,'GUARDIAN_EXTERNAL_BASELINE_SIGNATURE_AND_PAIR_MATCH');
  assert.equal(x.pinnedSignerSignatureValid,true);
  assert.equal(x.anchorSequence,seq);
  assert.match(x.journalSha256,/^[a-f0-9]{64}$/);
  assert.match(x.ledgerSha256,/^[a-f0-9]{64}$/);
  assert.match(x.signedPayloadSha256,/^[a-f0-9]{64}$/);
}
function injectedOpen(target,n,sideEffect,fn){
  const original=fs.openSync;
  let seen=0;
  fs.openSync=function(file,...args){
    if(typeof file==='string' &&
       path.resolve(file)===path.resolve(target) && ++seen===n){
      sideEffect();
    }
    return original.call(this,file,...args);
  };
  try{return fn();}
  finally {fs.openSync=original;}
}
test('constructor inert; no configured production pin or files are manufactured',async()=>{
  await workspace(async f=>{
    const before=fs.readdirSync(f.directory);
    const verifier=f.make();
    assert.ok(Object.isFrozen(verifier));
    assert.deepEqual(Object.keys(verifier),['verify']);
    assert.deepEqual(fs.readdirSync(f.directory),before);
    deny(verifier.verify('{}'),'GUARDIAN_EXTERNAL_BASELINE_ENVELOPE_INVALID');
    assert.deepEqual(fs.readdirSync(f.directory),before);
  });
});
test('synthetic Ed25519 contract plus complete owner-only pair matches locally, never proves external trust',async()=>{
  await workspace(async f=>{
    f.append();
    const envelope=f.signPacket();
    const bytes=JSON.stringify(envelope);
    const files=[fs.readFileSync(f.journal),fs.readFileSync(f.ledger)];
    const observed=f.make().verify(bytes);
    valid(observed);
    assert.equal(observed.journalSha256,sha(files[0]));
    assert.equal(observed.ledgerSha256,sha(files[1]));
    assert.deepEqual(fs.readFileSync(f.journal),files[0]);
    assert.deepEqual(fs.readFileSync(f.ledger),files[1]);
  });
});
test('sequence replay and rollback are rejected only within same ephemeral verifier instance',async()=>{
  await workspace(async f=>{
    f.append();
    const inst=f.make();
    valid(inst.verify(JSON.stringify(f.signPacket())));
    deny(inst.verify(JSON.stringify(f.signPacket())),
      'GUARDIAN_EXTERNAL_BASELINE_SEQUENCE_REPLAY');
    valid(inst.verify(JSON.stringify(f.signPacket({sequence:2}))),2);
    deny(inst.verify(JSON.stringify(f.signPacket({sequence:1}))),
      'GUARDIAN_EXTERNAL_BASELINE_SEQUENCE_REPLAY');
    // Restart does not establish durable replay protection. Still HOLD.
    valid(f.make().verify(JSON.stringify(f.signPacket())));
  });
});
test('changed envelope digests/count/sequence without valid signature is not verified',async()=>{
  await workspace(async f=>{
    f.append();
    const clean=f.signPacket();
    for(const update of [
      {journalSha256:'0'.repeat(64)}, {ledgerSha256:'1'.repeat(64)},
      {journalBytes:clean.journalBytes+1},
      {ledgerBytes:clean.ledgerBytes+1},
      {sequence:8},{anchorId:'synthetic-fake-anchor'},
    ]){
      const tampered={...clean,...update};
      deny(f.make().verify(JSON.stringify(tampered)),
        update.anchorId ?
          'GUARDIAN_EXTERNAL_BASELINE_ANCHOR_ID_MISMATCH' :
          'GUARDIAN_EXTERNAL_BASELINE_SIGNATURE_INVALID');
    }
  });
});
test('correctly signed wrong digest or number of bytes cannot override local source',async()=>{
  await workspace(async f=>{
    f.append();
    for(const changes of [
      {journalSha256:'0'.repeat(64)},
      {ledgerSha256:'0'.repeat(64)},
      {journalBytes:fs.statSync(f.journal).size+1},
      {ledgerBytes:fs.statSync(f.ledger).size+1},
    ]){
      deny(f.make().verify(JSON.stringify(f.signPacket(changes))),
        'GUARDIAN_EXTERNAL_BASELINE_PAIR_MISMATCH');
    }
  });
});
test('wrong anchor identity even if signed or wrong pinned public-key fingerprint is rejected',async()=>{
  await workspace(async f=>{
    f.append();
    deny(f.make().verify(JSON.stringify(f.signPacket({
      anchorId:'different-test-anchor',
    }))), 'GUARDIAN_EXTERNAL_BASELINE_ANCHOR_ID_MISMATCH');
    assert.throws(()=>f.make({pinnedSpkiSha256:'0'.repeat(64)}),
      /GUARDIAN_EXTERNAL_BASELINE_PIN_UNVERIFIED/);
    const foreign=syntheticSigner();
    assert.throws(()=>f.make({publicKeyPem:foreign.publicKeyPem}),
      /GUARDIAN_EXTERNAL_BASELINE_PIN_UNVERIFIED/);
    const badSignature={...f.signPacket(),signatureBase64:'Z'.repeat(86)+'=='};
    deny(f.make().verify(JSON.stringify(badSignature)),
      'GUARDIAN_EXTERNAL_BASELINE_ENVELOPE_INVALID');
  });
});
test('syntactically duplicate JSON keys, unsafe metadata and unexpected props reject before file reads',async()=>{
  await workspace(async f=>{
    f.append();
    const good=JSON.stringify(f.signPacket());
    const cases=[
      good.replace('"sequence":1','"sequence":1,"sequence":2'),
      good.replace('"journalSha256":"','"journalSha256":"0","journalSha256":"'),
      good+'TRAILING_TOKEN',
      good.replace('"algorithm":"Ed25519"',
        '"algorithm":"RSA"'),
      JSON.stringify({...f.signPacket(),token:'PRIVATE_KEY'}),
      ' '.repeat(8300),'{bad',
    ];
    for(const input of cases){
      const x=f.make().verify(input);
      hold(x);
      assert.equal(x.comparison,'NOT_VERIFIED');
      assert.equal(x.journalSha256,null);
      assert.ok(!JSON.stringify(x).includes('PRIVATE_KEY'));
    }
    for(const obj of [{},Buffer.from(good),null,1,[]]){
      deny(f.make().verify(obj),'GUARDIAN_EXTERNAL_BASELINE_INPUT_INVALID');
    }
  });
});
test('dangerous constructor configuration and private-key PEM rejected without creating files',async()=>{
  await workspace(async f=>{
    for(const config of [
      {directory:'relative/path'},
      {fileName:'../secret.jsonl'},
      {expectedAnchorId:'not valid'},
      {pinnedSpkiSha256:'bad'},
      {publicKeyPem:'-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----'},
      {maxBytes:12},
      {maxBytes:50000000},
      {unexpected:'TOKEN'},
    ]){
      assert.throws(()=>f.make(config));
    }
    assert.throws(()=>createGuardianExternalBaselineVerifier(
      new Proxy({}, {ownKeys(){throw Error('PRIVATE_TOKEN');}})),
      /GUARDIAN_EXTERNAL_BASELINE_CONFIG_INVALID/);
    assert.deepEqual(fs.readdirSync(f.directory),[]);
  });
});
test('first unobserved double absence cannot mint a matching signed baseline',async()=>{
  await workspace(async f=>{
    f.append();
    const signed=JSON.stringify(f.signPacket());
    fs.unlinkSync(f.ledger);fs.unlinkSync(f.journal);
    deny(f.make().verify(signed),
      'GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED');
    assert.deepEqual(fs.readdirSync(f.directory),[]);
  });
});
test('truncated, duplicate terminal receipt and forged launch ledger reject even signed matching file hashes',async()=>{
  await workspace(async f=>{
    f.append();
    const journal=fs.readFileSync(f.journal);
    const ledger=fs.readFileSync(f.ledger);
    for(const [filename,bytes,reason] of [
      [f.journal,journal.subarray(0,journal.length-1),
        'GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED'],
      [f.journal,Buffer.concat([journal,journal]),
        'GUARDIAN_EXTERNAL_BASELINE_RECONCILIATION_UNVERIFIED'],
      [f.ledger,Buffer.concat([ledger,ledger]),
        'GUARDIAN_EXTERNAL_BASELINE_RECONCILIATION_UNVERIFIED'],
      [f.ledger,Buffer.from(ledger.toString('utf8').replace(
        '"schemaVersion":1,','"schemaVersion":1,"schemaVersion":1,')),
        'GUARDIAN_EXTERNAL_BASELINE_RECONCILIATION_UNVERIFIED'],
    ]){
      fs.writeFileSync(f.journal,journal);
      fs.writeFileSync(f.ledger,ledger);
      assert.equal(bytes.equals(filename===f.journal?journal:ledger),false);
      fs.writeFileSync(filename,bytes);
      const sign=JSON.stringify(f.signPacket());
      deny(f.make().verify(sign),reason);
    }
  });
});
test('file symlink, hardlink or weak permission mode cannot match even correct signature',async()=>{
  await workspace(async f=>{
    f.append();
    const signed=JSON.stringify(f.signPacket());
    fs.chmodSync(f.journal,0o644);
    deny(f.make().verify(signed),'GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED');
    fs.chmodSync(f.journal,0o600);
    fs.linkSync(f.journal,f.journal+'.hard');
    deny(f.make().verify(signed),'GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED');
    fs.unlinkSync(f.journal+'.hard');
    const contents=fs.readFileSync(f.ledger);
    fs.unlinkSync(f.ledger);
    fs.symlinkSync('/dev/null',f.ledger);
    deny(f.make().verify(signed),'GUARDIAN_EXTERNAL_BASELINE_SOURCE_UNVERIFIED');
  });
});
test('terminal append while local ledger is being opened returns rejection, no stale match',async()=>{
  await workspace(async f=>{
    f.append();
    const signed=JSON.stringify(f.signPacket());
    const result=injectedOpen(f.ledger,1,()=>{
      // Safe synthetic legacy receipt: journal changes, ledger stable.
      f.writer.append({
        state:'STOPPED',errorCode:null,hostStopped:true,
        activationAllowed:false,releaseAuthority:'NOT_ISSUED',
        automaticRestartAllowed:false,
      });
    },()=>f.make().verify(signed));
    hold(result);
    assert.equal(result.comparison,'NOT_VERIFIED');
    assert.equal(result.journalSha256,null);
  });
});
test('new signed snapshot with append after baseline can match with increasing sequence',async()=>{
  await workspace(async f=>{
    f.append();
    const v=f.make();
    valid(v.verify(JSON.stringify(f.signPacket())));
    f.append('STOPPED');
    valid(v.verify(JSON.stringify(f.signPacket({sequence:2}))),2);
  });
});
