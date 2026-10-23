/**
 * Fetch one off-repository policy envelope from a separately administered
 * HTTPS origin, then verify its Ed25519 signature with an independently pinned
 * trust key. No release or success decision can originate from this module.
 *
 * The owner host, NOT the candidate PR, must protect the hostname, public key,
 * fingerprint and administrator-separation policy. Source cannot prove that
 * two infrastructure operators are organizationally independent.
 */
'use strict';

const https = require('node:https');
const crypto = require('node:crypto');
const net = require('node:net');
const { verifySignedPolicy } = require('./signed-policy.cjs');

const SHA = /^[0-9a-f]{40}$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const MAX_POLICY_BYTES = 196_608;

class GuardianPolicySourceError extends Error {
  constructor(code) {
    super(code); this.name = 'GuardianPolicySourceError'; this.code = code;
  }
}
function assert(ok, code) {
  if (!ok) throw new GuardianPolicySourceError(code);
}
function verifiedAuthorityConfig({ hostname, publicKeyPem, pinnedSpkiSha256 }) {
  assert(typeof hostname === 'string' && hostname.length <= 253 &&
    /^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(hostname) &&
    net.isIP(hostname) === 0 &&
    hostname !== 'api.github.com' && !hostname.endsWith('.github.com') &&
    !hostname.endsWith('.githubusercontent.com') &&
    !['.localhost', '.local', '.internal', '.test', '.invalid'].some(
      (suffix) => hostname.endsWith(suffix)) &&
    typeof publicKeyPem === 'string' && publicKeyPem.length < 10_000 &&
    FINGERPRINT.test(pinnedSpkiSha256),
  'POLICY_AUTHORITY_CONFIG_INVALID');
  let key;
  try {
    key = crypto.createPublicKey(publicKeyPem);
  } catch (_) { throw new GuardianPolicySourceError('POLICY_KEY_INVALID'); }
  assert(key.asymmetricKeyType === 'ed25519',
    'POLICY_KEY_NOT_ED25519');
  const actual = crypto.createHash('sha256').update(
    key.export({ format: 'der', type: 'spki' })).digest('hex');
  assert(crypto.timingSafeEqual(Buffer.from(actual, 'hex'),
    Buffer.from(pinnedSpkiSha256, 'hex')), 'POLICY_KEY_PIN_MISMATCH');
  return { hostname, publicKeyPem };
}

function readBoundedEnvelope(hostname, path) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname, port: 443, protocol: 'https:', method: 'GET', path,
      timeout: 8000,
      headers: {
        Accept: 'application/json',
        'Cache-Control': 'no-store',
        'User-Agent': 'nohands-guardian-inert-policy-reader/1',
      },
      agent: new https.Agent({ keepAlive: false, maxSockets: 1 }),
    }, (response) => {
      // No redirects, auth fallback or alternate URL. The envelope's Ed25519
      // signature is verified independently of the HTTPS transport.
      if (response.statusCode !== 200 ||
          !/^application\/json(?:;|$)/i.test(String(
            response.headers['content-type'] || ''))) {
        response.resume();
        reject(new GuardianPolicySourceError('POLICY_HTTP_OR_CONTENT_TYPE_INVALID'));
        return;
      }
      const advertised = Number(response.headers['content-length']);
      if (Number.isFinite(advertised) && advertised > MAX_POLICY_BYTES) {
        response.resume();
        reject(new GuardianPolicySourceError('POLICY_ENVELOPE_OVERSIZE'));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_POLICY_BYTES) {
          response.destroy(new GuardianPolicySourceError('POLICY_ENVELOPE_OVERSIZE'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => resolve(Buffer.concat(chunks)));
    });
    request.on('timeout', () => request.destroy(
      new GuardianPolicySourceError('POLICY_FETCH_TIMEOUT')));
    request.on('error', (error) => reject(error instanceof GuardianPolicySourceError ?
      error : new GuardianPolicySourceError('POLICY_FETCH_FAILED')));
    request.end();
  });
}

async function fetchIndependentlySignedPolicy({ authority, pullNumber, headSha }) {
  assert(Number.isSafeInteger(pullNumber) && pullNumber > 0 &&
    typeof headSha === 'string' && SHA.test(headSha),
  'POLICY_TARGET_INVALID');
  const config = verifiedAuthorityConfig(authority || {});
  const path = '/v1/guardian/signed-policies/' + pullNumber + '/' + headSha;
  const envelope = await readBoundedEnvelope(config.hostname, path);
  const result = verifySignedPolicy(envelope, config.publicKeyPem, {
    requirePullBinding: true, expectedPullNumber: pullNumber,
  });
  assert(result.signatureChecked === true && result.headSha === headSha &&
    result.pullNumber === pullNumber,
    'POLICY_SIGNATURE_SCOPE_OR_HEAD_INVALID');
  return {
    envelope, publicKeyPem: config.publicKeyPem,
    policyDigest: result.payloadSha256,
    result: 'SIGNATURE_AND_HEAD_VERIFIED_ONLY',
    activationAllowed: false,
  };
}

module.exports = {
  fetchIndependentlySignedPolicy, GuardianPolicySourceError,
};
