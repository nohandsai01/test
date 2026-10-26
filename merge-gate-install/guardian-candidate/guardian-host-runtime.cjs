/**
 * Protected Guardian host runtime adapter. It composes the EXISTING
 * createGuardianHttpServer / createGuardianD1Stores with one validated host
 * configuration and adds lifecycle control: start, bounded stop, restart.
 *
 * Importing this module starts nothing. Only an explicit start() call listens,
 * and only on a loopback address behind a separately operated TLS terminator.
 * No Check, D1, signature or reconciliation logic is re-implemented here.
 */
'use strict';

const { createGuardianHttpServer } = require('./guardian-http-server.cjs');
const { createGuardianD1Stores } = require('./guardian-d1-stores.cjs');
const { validateGuardianHostConfig, probeGuardianD1Schema,
  GuardianHostConfigError } = require('./guardian-host-bootstrap.cjs');

const OAUTH_CALLBACK = '/guardian/install/oauth/callback';

class GuardianHostRuntimeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GuardianHostRuntimeError';
    this.code = code;
  }
}

/**
 * Every injected dependency call is bounded and fenced to one host
 * generation. A timed-out or post-stop result is a rejection, which the
 * existing D1 stores and HTTP handlers already convert into HOLD. A late
 * D1 success can therefore never resume a pipeline toward Check egress.
 */
function generationGuard(generation, timeoutMs) {
  return function call(fn, thisArg, args) {
    return new Promise((resolve, reject) => {
      if (!generation.open) {
        reject(new Error('GUARDIAN_HOST_GENERATION_CLOSED'));
        return;
      }
      const timer = setTimeout(() =>
        reject(new Error('GUARDIAN_HOST_DEPENDENCY_TIMEOUT')), timeoutMs);
      Promise.resolve().then(() => fn.apply(thisArg, args)).then((value) => {
        clearTimeout(timer);
        if (generation.open) resolve(value);
        else reject(new Error('GUARDIAN_HOST_GENERATION_CLOSED'));
      }, (error) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error :
          new Error('GUARDIAN_HOST_DEPENDENCY_REJECTED'));
      });
    });
  };
}
function guardedFunction(call, fn, thisArg) {
  return (...args) => call(fn, thisArg, args);
}
function guardedD1(binding, call) {
  return Object.freeze({
    prepare(sql) {
      const statement = binding.prepare(sql);
      return Object.freeze({
        bind(...params) {
          const bound = statement.bind(...params);
          return Object.freeze({
            run: () => call(bound.run, bound, []),
            first: () => call(bound.first, bound, []),
          });
        },
      });
    },
  });
}

/**
 * Maps the validated configuration onto the existing host contracts. All
 * identities come from the single pinned githubApp section; callers cannot
 * pass a mismatched store, App ID or repository ID into one sub-handler.
 */
function buildHost(config, stores, call) {
  const app = config.githubApp;
  const mode = config.checkWrites.mode;
  const host = {
    webhookSecret: config.webhook.secret,
    trustedInstallationId: config.webhook.trustedInstallationId,
    guardianAppId: app.appId,
    expectedOwnerAccountId: app.expectedOwnerAccountId,
    expectedRepositoryId: app.expectedRepositoryId,
    githubAppPrivateKeyPem: app.privateKeyPem,
    installationStore: stores.installationStore,
    deliveryStore: stores.deliveryStore,
    conclusionStore: stores.conclusionStore,
    policyAuthority: { ...config.policyAuthority },
    enableFailureCheckWrites: mode === 'FAILURE_ONLY',
    founderAuthorizedFailureOnly: mode === 'FAILURE_ONLY' ?
      'EXPLICIT_FAILURE_ONLY' : null,
    enableFullCheckWrites: mode === 'FULL',
    founderAuthorizedFullMode: mode === 'FULL' ?
      'EXPLICIT_FULL_CHECK_WRITES' : null,
    enableOwnerOnboardingRoutes: config.ownerOnboarding !== null,
    enableReadOnlyOperatorRoutes: config.operatorReadOnly !== null,
  };
  const owner = config.ownerOnboarding;
  if (owner) {
    host.ownerOnboarding = {
      publicOrigin: owner.publicOrigin,
      authenticateOwnerRequest: guardedFunction(call, owner.authenticateOwnerRequest, null),
      verifyCsrf: guardedFunction(call, owner.verifyCsrf, null),
      rateLimiter: { allow: guardedFunction(call, owner.rateLimiter.allow,
        owner.rateLimiter) },
      intentStore: stores.intentStore, oauthStore: stores.oauthStore,
      installationStore: stores.installationStore,
      appSlug: owner.appSlug, appId: app.appId,
      expectedOwnerAccountId: app.expectedOwnerAccountId,
      redirectUri: owner.publicOrigin + OAUTH_CALLBACK,
      clientId: owner.clientId, clientSecret: owner.clientSecret,
      privateKeyPem: app.privateKeyPem,
    };
  }
  const operator = config.operatorReadOnly;
  if (operator) {
    host.operatorReadOnly = {
      publicOrigin: operator.publicOrigin,
      ownerAccountId: app.expectedOwnerAccountId,
      repositoryId: app.expectedRepositoryId,
      guardianAppId: app.appId,
      // Least privilege: the operator route receives the read-only lookup
      // only, never reserveOnce or any other D1 mutation.
      conclusionStore: Object.freeze({
        getReservation: stores.conclusionStore.getReservation,
      }),
      authenticateOwnerRequest: guardedFunction(call,
        operator.authenticateOwnerRequest, null),
      verifyCsrf: guardedFunction(call, operator.verifyCsrf, null),
      rateLimiter: { allow: guardedFunction(call, operator.rateLimiter.allow,
        operator.rateLimiter) },
      issueReadOnlyToken: guardedFunction(call, operator.issueReadOnlyToken, null),
      ...(operator.requestTimeoutMs === undefined ? {} :
        { requestTimeoutMs: operator.requestTimeoutMs }),
    };
  }
  return host;
}

function listen(server, { host, port }) {
  return new Promise((resolve, reject) => {
    const failed = (error) => reject(error);
    server.once('error', failed);
    server.listen({ host, port, exclusive: true }, () => {
      server.removeListener('error', failed);
      resolve();
    });
  });
}

/**
 * Configuration is validated synchronously: an incomplete or contradictory
 * trust configuration throws here and no runtime object is ever returned.
 */
function createGuardianProtectedHost(rawConfig) {
  const config = validateGuardianHostConfig(rawConfig);
  let state = 'STOPPED';
  let server = null;
  let generation = null;
  const sockets = new Set();

  async function start() {
    if (state !== 'STOPPED') {
      throw new GuardianHostRuntimeError('GUARDIAN_HOST_NOT_STOPPED');
    }
    state = 'STARTING';
    const current = { open: true };
    let candidate = null;
    try {
      const call = generationGuard(current, config.dependencyTimeoutMs);
      const d1 = guardedD1(config.d1Binding, call);
      await probeGuardianD1Schema(d1);
      const stores = createGuardianD1Stores(d1);
      // Owner/operator handlers throw on any missing dependency at setup.
      candidate = createGuardianHttpServer({ host: buildHost(config, stores, call) });
      candidate.on('connection', (socket) => {
        sockets.add(socket);
        socket.once('close', () => sockets.delete(socket));
      });
      // A malformed client never affects other connections or the process.
      candidate.on('clientError', (_, socket) => socket.destroy());
      await listen(candidate, config.listen);
    } catch (error) {
      current.open = false;
      if (candidate?.listening) candidate.close();
      state = 'STOPPED';
      throw new GuardianHostRuntimeError(error instanceof GuardianHostConfigError ?
        error.code : 'GUARDIAN_HOST_START_REFUSED');
    }
    generation = current;
    server = candidate;
    state = 'RUNNING';
    return address();
  }

  async function stop() {
    if (state === 'STOPPED') return;
    if (state !== 'RUNNING') {
      throw new GuardianHostRuntimeError('GUARDIAN_HOST_TRANSITION_IN_PROGRESS');
    }
    state = 'STOPPING';
    // Fence first: in-flight pipelines lose D1 and owner authority before
    // the listener drains, so nothing started before stop() reaches egress
    // through a later dependency result.
    generation.open = false;
    const closing = server;
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        closing.closeAllConnections();
        for (const socket of sockets) socket.destroy();
      }, config.drainTimeoutMs);
      closing.close(() => { clearTimeout(timer); resolve(); });
      closing.closeIdleConnections();
    });
    server = null;
    generation = null;
    state = 'STOPPED';
  }

  async function restart() {
    await stop();
    return start();
  }

  function address() {
    if (state !== 'RUNNING' || !server) return null;
    const a = server.address();
    return Object.freeze({ host: a.address, port: a.port });
  }

  return Object.freeze({
    start, stop, restart, address,
    state: () => state,
  });
}

module.exports = { createGuardianProtectedHost, GuardianHostRuntimeError };
