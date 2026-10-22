/**
 * GitHub App installation-intent primitives. An installation redirect is NOT
 * proof of App installation, repository permission or installer identity.
 * No installation is activated by any return value from this module.
 */
'use strict';

const crypto = require('node:crypto');
const { verifyOwnerInstallationBinding } =
  require('./github-app-identity.cjs');

function hold(reason) {
  return { status: 'INSTALLATION_HOLD', reason, installed: false,
    activated: false, accountVerified: false };
}
function stateDigest(state) {
  return crypto.createHash('sha256').update(state).digest('hex');
}
function validSlug(slug) {
  return typeof slug === 'string' && /^[a-z0-9][a-z0-9-]{1,98}$/.test(slug);
}

/** `intentStore.putIfAbsent` must be durable, atomic, and outside this repo. */
async function beginGuardianInstallation({ appSlug, verifiedOwnerSessionId, intentStore }) {
  if (!validSlug(appSlug) || typeof verifiedOwnerSessionId !== 'string' ||
      verifiedOwnerSessionId.length < 16 || verifiedOwnerSessionId.length > 256 ||
      !intentStore || typeof intentStore.putIfAbsent !== 'function') {
    return hold('INSTALLATION_HOST_OR_OWNER_SESSION_UNVERIFIED');
  }
  const state = crypto.randomBytes(32).toString('base64url');
  const digest = stateDigest(state);
  try {
    if (await intentStore.putIfAbsent({ stateSha256: digest,
      ownerSessionId: verifiedOwnerSessionId,
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    }) !== true) return hold('INSTALLATION_STATE_NOT_PERSISTED');
  } catch (_) { return hold('INSTALLATION_STATE_STORE_FAILURE'); }
  return {
    status: 'INSTALLATION_LINK_ISSUED_NOT_AUTHORIZED',
    url: `https://github.com/apps/${appSlug}/installations/new?state=${state}`,
    activated: false, installed: false, accountVerified: false,
  };
}

/**
 * Setup redirects are user-controlled HTTP requests, including installation_id.
 * Even a matching single-use state never establishes ownership. A protected
 * onboarding host must OAuth-bind the user access token to the verified owner
 * session and supply a pinned numeric GitHub account ID from outside PR code.
 */
async function consumeGuardianSetupIntent({ state, installationId, setupAction,
  verifiedOwnerSessionId, intentStore, installationStore, appId, privateKeyPem,
  ownerUserAccessToken, expectedOwnerAccountId }) {
  if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(state) ||
      !Number.isSafeInteger(installationId) || installationId <= 0 ||
      !['install', 'update'].includes(setupAction) ||
      typeof verifiedOwnerSessionId !== 'string' ||
      !intentStore || typeof intentStore.consumeIfOwnerAndUnexpired !== 'function') {
    return hold('SETUP_REDIRECT_OR_STATE_INVALID');
  }
  try {
    const used = await intentStore.consumeIfOwnerAndUnexpired({
      stateSha256: stateDigest(state), ownerSessionId: verifiedOwnerSessionId,
      now: new Date().toISOString(),
    });
    if (used !== true) return hold('SETUP_STATE_MISMATCH_EXPIRED_OR_REPLAYED');
  } catch (_) { return hold('SETUP_STATE_STORE_FAILURE'); }
  if (!installationStore || typeof installationStore.bindVerifiedOnce !== 'function') {
    return hold('INSTALLATION_BINDING_STORE_UNAVAILABLE');
  }
  let binding;
  try {
    binding = await verifyOwnerInstallationBinding({
      installationId, appId, privateKeyPem, ownerUserAccessToken,
      expectedOwnerAccountId,
    });
  } catch (_) {
    return hold('GITHUB_OWNER_INSTALLATION_BINDING_NOT_VERIFIED');
  }
  try {
    if (await installationStore.bindVerifiedOnce(binding) !== true) {
      return hold('INSTALLATION_ALREADY_BOUND_OR_WRITE_UNCONFIRMED');
    }
  } catch (_) { return hold('INSTALLATION_BINDING_STORE_FAILURE'); }
  return {
    status: 'INSTALLATION_VERIFIED_NOT_ACTIVATED',
    installationId: binding.installationId,
    appId: binding.appId,
    ownerAccountId: binding.ownerAccountId,
    repositoryId: binding.repositoryId,
    accountVerified: true, installed: true, activated: false,
    releaseAuthority: 'NOT_ISSUED',
  };
}

module.exports = { beginGuardianInstallation, consumeGuardianSetupIntent };
