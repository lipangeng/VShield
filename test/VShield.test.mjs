import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const SOURCE = await fs.readFile(new URL('../VShield.js', import.meta.url), 'utf8');

class SharedDictMock {
  constructor() {
    this.map = new Map();
    this.setCalls = [];
  }

  set(key, value, ttl) {
    this.setCalls.push({ key, value, ttl });
    this.map.set(key, value);
  }

  get(key) {
    return this.map.get(key);
  }

  delete(key) {
    this.map.delete(key);
  }

  keys() {
    return this.map.keys();
  }
}

async function loadVShield(shared) {
  globalThis.ngx = { shared: { vs_ip: shared } };
  const encoded = Buffer.from(SOURCE, 'utf8').toString('base64');
  const mod = await import(`data:text/javascript;base64,${encoded}#${Date.now()}-${Math.random()}`);
  return mod.default;
}

function createRequest(overrides = {}) {
  const logs = [];
  const errors = [];
  let returned = null;

  return {
    remoteAddress: '203.0.113.10',
    remoteUser: '',
    variables: {},
    headersIn: {},
    headersOut: {},
    args: {},
    log(msg) {
      logs.push(msg);
    },
    error(msg) {
      errors.push(msg);
    },
    return(status, body) {
      returned = { status, body };
    },
    get _logs() {
      return logs;
    },
    get _errors() {
      return errors;
    },
    get _returned() {
      return returned;
    },
    ...overrides
  };
}

function withFixedNow(now, fn) {
  const original = Date.now;
  Date.now = () => now;
  try {
    return fn();
  } finally {
    Date.now = original;
  }
}

test('register should store current IP and write audit log', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const r = createRequest({
    variables: { vshield_user: 'alice@example.com' }
  });

  withFixedNow(1_700_000_000_000, () => VShield.register(r));

  assert.equal(r._returned.status, 200);
  assert.match(r._returned.body, /203\.0\.113\.10 is registered/);
  assert.equal(shared.setCalls.length, 1);
  assert.equal(shared.setCalls[0].ttl, 7_200_000);
  assert.equal(shared.get('203.0.113.10'), 1_700_007_200_000);
  assert.ok(r._logs.some((line) => line.includes('action=register_self')));
  assert.ok(r._logs.some((line) => line.includes('actor=alice@example.com')));
});

test('register should reject missing client IP', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const r = createRequest({ remoteAddress: '' });

  VShield.register(r);

  assert.equal(r._returned.status, 400);
  assert.equal(r._returned.body, 'Missing client IP');
  assert.equal(shared.setCalls.length, 0);
});

test('http_verify should allow registered IP', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const now = 1_700_000_000_000;
  shared.set('203.0.113.10', now + 10_000_000, 10_000_000);
  const r = createRequest();

  withFixedNow(now, () => VShield.http_verify(r));

  assert.equal(r._returned.status, 200);
  assert.equal(r._returned.body, 'OK');
});

test('http_verify should deny unregistered IP and set reason header', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const r = createRequest({ remoteAddress: '198.51.100.20' });

  VShield.http_verify(r);

  assert.equal(r._returned.status, 403);
  assert.equal(r.headersOut['X-VShield-Reason'], 'IP_NOT_REGISTERED');
  assert.match(r._returned.body, /not registered/);
});

test('http_verify should refresh near-expiry record', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const now = 1_700_000_000_000;
  shared.set('203.0.113.10', now + 1_000, 1_000);
  const r = createRequest();

  withFixedNow(now, () => VShield.http_verify(r));

  assert.equal(r._returned.status, 200);
  assert.equal(shared.get('203.0.113.10'), now + 7_200_000);
  assert.ok(shared.setCalls.length >= 2);
});

test('adminRegister should respect timeout and include audit detail', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const now = 1_700_000_000_000;
  const r = createRequest({
    args: { ip: '192.0.2.8', timeout: '600000' },
    variables: { vshield_user: 'admin' }
  });

  withFixedNow(now, () => VShield.adminRegister(r));

  assert.equal(r._returned.status, 200);
  assert.equal(shared.get('192.0.2.8'), now + 600_000);
  assert.ok(r._logs.some((line) => line.includes('action=admin_register')));
  assert.ok(r._logs.some((line) => line.includes('detail=ttl_ms=600000')));
});

test('adminRegister should fallback to default ttl for invalid timeout', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const now = 1_700_000_000_000;
  const r = createRequest({ args: { ip: '192.0.2.99', timeout: 'abc' } });

  withFixedNow(now, () => VShield.adminRegister(r));

  assert.equal(r._returned.status, 200);
  assert.equal(shared.get('192.0.2.99'), now + 7_200_000);
});

test('adminWhiteList should return json and skip invalid entries', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  shared.set('192.0.2.1', 1_700_000_010_000, 1_000);
  shared.set('192.0.2.2', 'not-a-number', 1_000);
  const r = createRequest();

  VShield.adminWhiteList(r);

  assert.equal(r._returned.status, 200);
  assert.equal(r.headersOut['Content-Type'], 'application/json; charset=utf-8');
  const rows = JSON.parse(r._returned.body);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].ip, '192.0.2.1');
});

test('stream_verify should allow registered stream session', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);
  const now = 1_700_000_000_000;
  shared.set('203.0.113.10', now + 10_000_000, 10_000_000);

  let allowed = false;
  let denied = false;
  const s = {
    remoteAddress: '203.0.113.10',
    allow() { allowed = true; },
    deny() { denied = true; },
    log() {},
    error() {}
  };

  withFixedNow(now, () => VShield.stream_verify(s));

  assert.equal(allowed, true);
  assert.equal(denied, false);
});

test('stream_verify should deny unregistered stream session', async () => {
  const shared = new SharedDictMock();
  const VShield = await loadVShield(shared);

  let allowed = false;
  let denied = false;
  const s = {
    remoteAddress: '203.0.113.250',
    allow() { allowed = true; },
    deny() { denied = true; },
    log() {},
    error() {}
  };

  VShield.stream_verify(s);

  assert.equal(allowed, false);
  assert.equal(denied, true);
});
