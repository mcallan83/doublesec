import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { createContext, runInContext } from 'node:vm';
import { build } from 'vite-plus';
import { beforeAll, test, vi } from 'vite-plus/test';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToString,
  decrypt,
  encrypt,
  stringToBytes,
} from '../src/index.ts';

test('round-trips UTF-8 text with a byte passphrase', async () => {
  const passphrase = stringToBytes('clé 🔑');
  const text = '\uFEFFHello 🌎';
  const data = stringToBytes(text);
  const ciphertext = await encrypt({ passphrase, data });
  const decoded = await decrypt({ passphrase, data: ciphertext });
  assert.deepEqual(decoded, data);
  assert.equal(bytesToString(decoded), text);
});

test('converts UTF-8 text and bytes without modifying them and rejects invalid UTF-8', () => {
  const bytes = Uint8Array.of(0xef, 0xbb, 0xbf, 0x61);
  assert.deepEqual(stringToBytes('\uFEFFa'), bytes);
  assert.equal(bytesToString(bytes), '\uFEFFa');
  assert.deepEqual(bytes, Uint8Array.of(0xef, 0xbb, 0xbf, 0x61));
  assert.throws(() => bytesToString(Uint8Array.of(0xff)), TypeError);
});

const vector = JSON.parse(readFileSync(new URL('./keybase-v4.json', import.meta.url)));
const passphrase = Buffer.from(vector.key, 'hex');
const plaintext = Buffer.from(vector.pt, 'hex');
const ciphertext = Buffer.from(vector.ct, 'hex');
const randomTape = Buffer.from(vector.r, 'hex');
let browserScript;

test('Base64 helpers round-trip binary data and match Node Base64', () => {
  const bytes = Buffer.alloc(100_001);
  for (let index = 0; index < bytes.length; index++) bytes[index] = index % 256;
  const encoded = bytesToBase64(bytes);
  assert.equal(encoded, bytes.toString('base64'));
  assert.deepEqual(Buffer.from(base64ToBytes(encoded)), bytes);
  assert.equal(bytesToBase64(new Uint8Array()), '');
  assert.deepEqual(base64ToBytes(''), new Uint8Array());
  assert.throws(() => base64ToBytes('%%%'), { name: 'InvalidCharacterError' });
});

test('rejects missing and non-byte inputs to encrypt and decrypt', async () => {
  const invalidValues = [
    undefined,
    null,
    '',
    'text',
    0,
    [],
    new Uint8ClampedArray(),
    { [Symbol.toStringTag]: 'Uint8Array' },
  ];
  const invalidData = { name: 'TypeError', message: 'Data must be a Uint8Array' };
  const invalidPassphrase = { name: 'TypeError', message: 'Passphrase must be a Uint8Array' };

  for (const operation of [encrypt, decrypt]) {
    await assert.rejects(operation({ passphrase }), invalidData);
    await assert.rejects(operation({ data: ciphertext }), invalidPassphrase);
    for (const value of invalidValues) {
      await assert.rejects(operation({ data: value, passphrase }), invalidData);
      await assert.rejects(operation({ data: ciphertext, passphrase: value }), invalidPassphrase);
    }
  }
});

test('rejects empty passphrases and accepts cross-realm byte arrays', async () => {
  const emptyPassphrase = new Uint8Array();
  const plaintext = stringToBytes('passphrase validation');
  await assert.rejects(
    encrypt({ passphrase: emptyPassphrase, data: plaintext }),
    /Passphrase must not be empty/,
  );
  await assert.rejects(
    decrypt({ passphrase: emptyPassphrase, data: ciphertext }),
    /Passphrase must not be empty/,
  );

  const crossRealmPassphrase = runInContext('new Uint8Array([1, 2, 3])', createContext());
  const data = await encrypt({ passphrase: crossRealmPassphrase, data: plaintext });
  assert.deepEqual(await decrypt({ passphrase: crossRealmPassphrase, data }), plaintext);
});

async function buildFiles(mode) {
  const output = await build({ mode, build: { write: false } });
  const bundles = Array.isArray(output) ? output : [output];
  return bundles.flatMap((bundle) => bundle.output);
}

beforeAll(async () => {
  const files = await buildFiles('production');
  const entry = files.find((file) => file.type === 'chunk' && file.isEntry);
  assert.ok(entry, 'Expected a classic-script entry from the Vite build');
  assert.equal(entry.fileName, 'doublesec.js');
  browserScript = entry.code;
});

test('builds the standalone demo', async () => {
  const files = await buildFiles('standalone-demo');
  assert.deepEqual(new Set(files.map((file) => file.fileName)), new Set(['demo.html']));
  const demo = files.find((file) => file.fileName === 'demo.html').source;
  assert.match(demo, /<script>[\s\S]+<\/script>/);
  assert.doesNotMatch(demo, /<script[^>]+(?:src|type)=/);
});

function browserBundle(crypto) {
  const context = createContext({
    atob,
    btoa,
    crypto,
    DOMException,
    TextEncoder,
    TextDecoder,
    setTimeout,
    Uint8Array,
  });
  runInContext(browserScript, context);
  return context.DoubleSec;
}

test('decrypts the Keybase vector through the TypeScript entry', async () => {
  assert.deepEqual(Buffer.from(await decrypt({ passphrase, data: ciphertext })), plaintext);
});

for (const subtle of [webcrypto.subtle, undefined]) {
  test(`classic script matches the Keybase vector with ${subtle ? 'native crypto' : 'JavaScript fallback'}`, async () => {
    const bundle = browserBundle({
      subtle,
      getRandomValues(bytes) {
        assert.equal(bytes.length, randomTape.length);
        bytes.set(randomTape);
        return bytes;
      },
    });
    assert.deepEqual(
      Buffer.from(await bundle.encrypt({ passphrase, data: plaintext })),
      ciphertext,
    );
    assert.deepEqual(
      Buffer.from(
        await bundle.decrypt({
          passphrase,
          data: bundle.base64ToBytes(bundle.bytesToBase64(ciphertext)),
        }),
      ),
      plaintext,
    );
  });
}

test('decrypts through the TypeScript entry when Web Crypto is absent', async ({
  onTestFinished,
}) => {
  vi.stubGlobal('crypto', undefined);
  onTestFinished(() => vi.unstubAllGlobals());
  assert.deepEqual(Buffer.from(await decrypt({ passphrase, data: ciphertext })), plaintext);
  await assert.rejects(encrypt({ passphrase, data: plaintext }), /getRandomValues/);
});

test('falls back independently when native AES and HMAC are unavailable', async ({
  onTestFinished,
}) => {
  const importKey = vi.fn(async (_format, _key, algorithm) => {
    if (algorithm === 'AES-CTR') throw new DOMException('Unavailable AES', 'NotSupportedError');
    if (algorithm.name === 'HMAC') throw new DOMException('Blocked HMAC', 'SecurityError');
    throw new Error('Unexpected native algorithm');
  });
  vi.stubGlobal('crypto', { subtle: { importKey } });
  onTestFinished(() => vi.unstubAllGlobals());

  assert.deepEqual(Buffer.from(await decrypt({ passphrase, data: ciphertext })), plaintext);
  assert.deepEqual(
    importKey.mock.calls.map(([, , algorithm]) =>
      typeof algorithm === 'string' ? algorithm : algorithm.name,
    ),
    ['HMAC', 'AES-CTR'],
  );
});

test('propagates unexpected native crypto failures', async ({ onTestFinished }) => {
  const failure = new Error('Unexpected native failure');
  vi.stubGlobal('crypto', {
    subtle: {
      importKey: async () => {
        throw failure;
      },
    },
  });
  onTestFinished(() => vi.unstubAllGlobals());
  await assert.rejects(decrypt({ passphrase, data: ciphertext }), (error) => error === failure);
});

test('fresh salt and nonces produce different ciphertext, including for empty input', async () => {
  const data = new Uint8Array(0);
  const first = await encrypt({ passphrase, data });
  const second = await encrypt({ passphrase, data });
  assert.equal(first.length, 192);
  assert.notDeepEqual(first, second);
  assert.deepEqual(await decrypt({ passphrase, data: first }), data);
});

test('rejects malformed headers, legacy versions, tampering, and wrong passwords', async () => {
  await assert.rejects(
    decrypt({ passphrase, data: ciphertext.subarray(0, 7) }),
    /Invalid TripleSec header/,
  );
  await assert.rejects(decrypt({ passphrase, data: ciphertext.subarray(0, 191) }), /Truncated/);
  const old = Buffer.from(ciphertext);
  old[7] = 1;
  await assert.rejects(decrypt({ passphrase, data: old }), /Unsupported TripleSec version 1/);
  for (const offset of [8, 24, 88, 152, ciphertext.length - 1]) {
    const tampered = Buffer.from(ciphertext);
    tampered[offset] ^= 1;
    await assert.rejects(decrypt({ passphrase, data: tampered }), /authentication failed/);
  }
  await assert.rejects(
    decrypt({ passphrase: Uint8Array.of(1), data: ciphertext }),
    /authentication failed/,
  );
});

test('fails closed without a secure random source', async () => {
  await assert.rejects(
    browserBundle(undefined).encrypt({ passphrase, data: plaintext }),
    /getRandomValues/,
  );
});
