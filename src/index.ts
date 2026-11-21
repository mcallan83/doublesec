import { ctr } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { xsalsa20 } from '@noble/ciphers/salsa.js';

type Bytes = Uint8Array<ArrayBuffer>;

/** Byte input and passphrase for DoubleSec operations. */
export interface DoubleSecInput {
  /** Plaintext to encrypt or TripleSec v4 ciphertext to decrypt, as raw bytes. */
  data: Uint8Array;

  /** Non-empty passphrase bytes used for scrypt key derivation. */
  passphrase: Uint8Array;
}

const typedArrayPrototype: object = Object.getPrototypeOf(Uint8Array.prototype);

const MAGIC = 0x1c94d7de;
const VERSION = 4;
const HEADER_BYTES = 8;
const SALT_BYTES = 16;
const PREFIX_BYTES = HEADER_BYTES + SALT_BYTES;
const MAC_BYTES = 64;
const TAG_BYTES = 2 * MAC_BYTES;
const BODY_OFFSET = PREFIX_BYTES + TAG_BYTES;
const AES_IV_BYTES = 16;
const SALSA_IV_BYTES = 24;
const OVERHEAD = BODY_OFFSET + AES_IV_BYTES + SALSA_IV_BYTES;
const SHA3_KEY_OFFSET = 48;
const AES_KEY_OFFSET = 96;
const SALSA_KEY_OFFSET = 128;
const KEY_BYTES = 160;

function aesCtr(key: Bytes, counter: Bytes, data: Bytes): Promise<Bytes> {
  return preferNative(
    async (subtle) => {
      const imported = await subtle.importKey('raw', key, 'AES-CTR', false, ['encrypt']);
      const output = await subtle.encrypt(
        { name: 'AES-CTR', counter, length: 128 },
        imported,
        data,
      );
      return new Uint8Array(output);
    },
    () => ctr(key, counter).encrypt(data),
  );
}

/** Compute both authentication tags over the header, salt, and encrypted body. */
async function authenticate(keys: Bytes, prefix: Bytes, body: Bytes, tag: Bytes): Promise<void> {
  const sha512Key = keys.subarray(0, SHA3_KEY_OFFSET);
  await preferNative(
    async (subtle) => {
      const input = new Uint8Array(prefix.length + body.length);
      input.set(prefix);
      input.set(body, prefix.length);
      const imported = await subtle.importKey(
        'raw',
        sha512Key,
        {
          name: 'HMAC',
          hash: 'SHA-512',
        },
        false,
        ['sign'],
      );
      tag.set(new Uint8Array(await subtle.sign('HMAC', imported, input)));
    },
    () =>
      hmac
        .create(sha512, sha512Key)
        .update(prefix)
        .update(body)
        .digestInto(tag.subarray(0, MAC_BYTES)),
  );
  hmac
    .create(sha3_512, keys.subarray(SHA3_KEY_OFFSET, AES_KEY_OFFSET))
    .update(prefix)
    .update(body)
    .digestInto(tag.subarray(MAC_BYTES));
}

/** Decodes standard Base64 into bytes. Throws if the input is malformed. */
export function base64ToBytes(data: string): Bytes {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let offset = 0; offset < binary.length; offset++) {
    bytes[offset] = binary.charCodeAt(offset);
  }
  return bytes;
}

/** Encodes bytes as standard, padded Base64 for storage or transport. */
export function bytesToBase64(data: Uint8Array): string {
  const chunks: string[] = [];
  // Use a multiple of three so only the final Base64 chunk can need padding.
  const chunkSize = 24 * 1024;
  for (let offset = 0; offset < data.length; offset += chunkSize) {
    chunks.push(btoa(String.fromCharCode(...data.subarray(offset, offset + chunkSize))));
  }
  return chunks.join('');
}

/** Decodes UTF-8 bytes, preserving a leading BOM and rejecting invalid UTF-8. */
export function bytesToString(data: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data);
}

/**
 * Authenticates and decrypts a TripleSec v4 ciphertext.
 *
 * @param input - The raw ciphertext and the passphrase bytes used to encrypt it.
 * @returns A new byte array containing the original plaintext.
 * @throws {TypeError} The promise rejects if `data` or `passphrase` is missing or has a type other than `Uint8Array`, or if the passphrase is empty.
 * @throws The promise rejects if the ciphertext is malformed, uses an unsupported
 * version, fails authentication, or cannot be decrypted.
 *
 * @remarks
 * Both authentication tags are verified before decryption. An incorrect passphrase
 * or modified ciphertext fails authentication. The input arrays are read without
 * being modified.
 */
export async function decrypt({ data, passphrase }: DoubleSecInput): Promise<Bytes> {
  validateBytes(data, 'Data');
  validatePassphrase(passphrase);
  const header = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length < HEADER_BYTES || header.getUint32(0) !== MAGIC) {
    throw new Error('Invalid TripleSec header');
  }
  const version = header.getUint32(4);
  if (version !== VERSION) throw new Error(`Unsupported TripleSec version ${version}`);
  if (data.length < OVERHEAD) throw new Error('Truncated TripleSec ciphertext');

  // Keep the authenticated bytes stable across asynchronous operations.
  const ciphertext = new Uint8Array(data);
  const body = ciphertext.subarray(BODY_OFFSET);
  const keys = await derive(passphrase, ciphertext.subarray(HEADER_BYTES, PREFIX_BYTES));
  try {
    const tag = new Uint8Array(TAG_BYTES);
    await authenticate(keys, ciphertext.subarray(0, PREFIX_BYTES), body, tag);
    let mismatch = 0;
    for (let i = 0; i < TAG_BYTES; i++) mismatch |= tag[i] ^ ciphertext[PREFIX_BYTES + i];
    if (mismatch !== 0) throw new Error('DoubleSec authentication failed');

    const inner = await aesCtr(
      keys.subarray(AES_KEY_OFFSET, SALSA_KEY_OFFSET),
      body.subarray(0, AES_IV_BYTES),
      body.subarray(AES_IV_BYTES),
    );
    try {
      return xsalsa20(
        keys.subarray(SALSA_KEY_OFFSET),
        inner.subarray(0, SALSA_IV_BYTES),
        inner.subarray(SALSA_IV_BYTES),
      );
    } finally {
      inner.fill(0);
    }
  } finally {
    keys.fill(0);
  }
}

/** Derive the v4 key material in wire-format order for the two MACs, AES, and XSalsa20. */
async function derive(passphrase: Uint8Array, salt: Bytes): Promise<Bytes> {
  const password = new Uint8Array(passphrase);
  try {
    return await scryptAsync(password, salt, { N: 32768, r: 8, p: 1, dkLen: KEY_BYTES });
  } finally {
    password.fill(0);
  }
}

/**
 * Encrypts bytes in the TripleSec v4 wire format.
 *
 * @param input - The plaintext and passphrase as `Uint8Array` values. Encode text with `stringToBytes` first.
 * @returns A new ciphertext byte array, 192 bytes longer than the plaintext.
 * @throws {TypeError} The promise rejects if `data` or `passphrase` is missing or has a type other than `Uint8Array`, or if the passphrase is empty.
 * @throws The promise rejects if secure randomness is unavailable or encryption fails.
 *
 * @remarks
 * Each call generates a fresh salt and initialization vectors using
 * `globalThis.crypto.getRandomValues`. Empty plaintext is allowed. The input
 * arrays are read without being modified.
 *
 * @example
 * ```ts
 * const ciphertext = await encrypt({ passphrase, data: stringToBytes('hello') });
 * ```
 */
export async function encrypt({ data, passphrase }: DoubleSecInput): Promise<Bytes> {
  validateBytes(data, 'Data');
  validatePassphrase(passphrase);
  const crypto = globalThis.crypto;
  if (typeof crypto?.getRandomValues !== 'function') {
    throw new Error('Encryption requires crypto.getRandomValues');
  }

  const random = crypto.getRandomValues(new Uint8Array(SALT_BYTES + AES_IV_BYTES + SALSA_IV_BYTES));
  const salt = random.subarray(0, SALT_BYTES);
  const aesIV = random.subarray(SALT_BYTES, SALT_BYTES + AES_IV_BYTES);
  const salsaIV = random.subarray(SALT_BYTES + AES_IV_BYTES);
  const output = new Uint8Array(OVERHEAD + data.length);
  const header = new DataView(output.buffer);
  header.setUint32(0, MAGIC);
  header.setUint32(4, VERSION);
  output.set(salt, HEADER_BYTES);
  output.set(aesIV, BODY_OFFSET);

  const inner = new Uint8Array(SALSA_IV_BYTES + data.length);
  inner.set(salsaIV);
  inner.set(data, SALSA_IV_BYTES);
  let keys: Bytes | undefined;
  try {
    keys = await derive(passphrase, salt);
    const payload = inner.subarray(SALSA_IV_BYTES);
    xsalsa20(keys.subarray(SALSA_KEY_OFFSET), salsaIV, payload, payload);
    output.set(
      await aesCtr(keys.subarray(AES_KEY_OFFSET, SALSA_KEY_OFFSET), aesIV, inner),
      BODY_OFFSET + AES_IV_BYTES,
    );
    await authenticate(
      keys,
      output.subarray(0, PREFIX_BYTES),
      output.subarray(BODY_OFFSET),
      output.subarray(PREFIX_BYTES, BODY_OFFSET),
    );
    return output;
  } finally {
    keys?.fill(0);
    inner.fill(0);
  }
}

/** Fall back when Web Crypto is absent, unsupported, or blocked by the environment. */
async function preferNative<T>(
  native: (subtle: SubtleCrypto) => Promise<T>,
  fallback: () => T,
): Promise<T> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    try {
      return await native(subtle);
    } catch (error) {
      if (
        !(error instanceof DOMException) ||
        (error.name !== 'NotSupportedError' && error.name !== 'SecurityError')
      ) {
        throw error;
      }
    }
  }
  return fallback();
}

/** Encodes a string as UTF-8 bytes. */
export function stringToBytes(data: string): Bytes {
  return new TextEncoder().encode(data);
}

function validateBytes(value: unknown, name: string): void {
  // Read the built-in typed-array brand to accept Buffers and cross-realm byte arrays.
  if (Reflect.get(typedArrayPrototype, Symbol.toStringTag, value) !== 'Uint8Array') {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

function validatePassphrase(value: Uint8Array): void {
  validateBytes(value, 'Passphrase');
  if (value.length === 0) throw new TypeError('Passphrase must not be empty');
}
