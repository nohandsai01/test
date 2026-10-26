'use strict';
// Worker used only by the synthetic SQLite integration test. No runtime
// credentials, network I/O or real Cloudflare D1 data are used.
const { parentPort, workerData } = require('node:worker_threads');
const { DatabaseSync } = require('node:sqlite');
const { createGuardianD1Stores } =
  require('../merge-gate-install/guardian-candidate/guardian-d1-stores.cjs');

const db = new DatabaseSync(workerData.dbFile);
db.exec('PRAGMA busy_timeout = 5000');
const d1 = {
  prepare(sql) {
    const stmt = db.prepare(sql);
    return {
      bind(...params) {
        return {
          async run() {
            const result = stmt.run(...params);
            return { success: true, meta: { changes: Number(result.changes) } };
          },
          async first() { return stmt.get(...params) ?? null; },
        };
      },
    };
  },
};
const stores = createGuardianD1Stores(d1);
parentPort.on('message', async (message) => {
  if (message !== 'go') return;
  try {
    const ok = await stores.conclusionStore.reserveOnce(workerData.claim);
    parentPort.postMessage({ ok });
  } catch (error) {
    parentPort.postMessage({ errorCode: error.code || 'UNEXPECTED' });
  } finally {
    db.close();
    parentPort.close();
  }
});
parentPort.postMessage({ ready: true });
