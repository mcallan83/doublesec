# DoubleSec

A TypeScript implementation of [Keybase TripleSec v4](https://keybase.io/triplesec) with a Promise API for browser and Node.js applications.

This library is named DoubleSec because TripleSec v4 has two encryption layers, not three: XSalsa20 encrypts the plaintext, then AES-CTR encrypts the XSalsa20 IV and inner ciphertext.

## Build

Use Node.js 22.18+ on the 22.x line, 24.11+ on the 24.x line, or 26+.

```sh
pnpm install
pnpm check
pnpm test
pnpm test --coverage
pnpm build
pnpm dev
```

| Command                | Purpose                                                        |
| ---------------------- | -------------------------------------------------------------- |
| `pnpm check`           | Run formatting, linting, and TypeScript checks.                |
| `pnpm test`            | Run the Vitest test suite.                                     |
| `pnpm test --coverage` | Run tests with V8 coverage.                                    |
| `pnpm build`           | Build the library, classic-script bundle, and standalone demo. |
| `pnpm dev`             | Start the Vite development server.                             |
| `pnpm lint`            | Run Oxlint only.                                               |
| `pnpm fmt`             | Apply the Prettier-compatible Oxfmt formatter.                 |
| `pnpm fmt --check`     | Check formatting without changing files.                       |

Build, lint, formatting, and test settings live in `vite.config.ts`.

- `dist/index.js` is the unminified ESM entry, with TypeScript declarations in `dist/index.d.ts`. It has named exports and imports individual Noble modules so application bundlers can tree-shake and minify the final build.
- `dist/doublesec.js` is the standalone browser bundle. The build minifies it and ships it under this filename. Load it with `<script src="./dist/doublesec.js"></script>` to use `globalThis.DoubleSec` without a module loader.
- `dist/demo.html` is a self-contained text demo. Open it directly from disk or serve it over HTTP. It makes no network requests.

## Usage

The package provides named ESM exports for Node.js and browser applications. Every `data` and `passphrase` argument must be a `Uint8Array`; strings are not accepted directly. Passphrases must contain at least one byte. The library does not assess passphrase strength.

| Function                          | What it does                                                             |
| --------------------------------- | ------------------------------------------------------------------------ |
| `encrypt`                         | Encrypts plaintext bytes and returns TripleSec v4 ciphertext bytes.      |
| `decrypt`                         | Authenticates ciphertext and returns the original plaintext bytes.       |
| `stringToBytes` / `bytesToString` | Convert between strings and UTF-8 bytes.                                 |
| `bytesToBase64` / `base64ToBytes` | Convert between bytes and standard Base64 text for storage or transport. |

Use the same passphrase bytes to encrypt and decrypt. If starting with a passphrase string, convert it to UTF-8 once and retain or recreate those same bytes when decrypting.

TripleSec v4 ciphertext is always 192 bytes longer than its plaintext. For strings, the plaintext size is the UTF-8 byte length, not the number of characters. Each encryption uses a fresh random salt and initialization vectors, so encrypting identical inputs twice produces different ciphertexts.

### Encrypt And Decrypt Text

Encode both the passphrase and message with `stringToBytes`. `decrypt` returns bytes; use `bytesToString` to decode text.

```ts
import { bytesToString, decrypt, encrypt, stringToBytes } from 'doublesec';

const passphrase = stringToBytes('replace with a strong passphrase');
const data = stringToBytes('Hello, 世界 👋');

const ciphertext = await encrypt({ passphrase, data });

const decryptedBytes = await decrypt({ passphrase, data: ciphertext });

const plaintext = bytesToString(decryptedBytes);

console.log(plaintext); // Hello, 世界 👋
```

### Encrypt And Decrypt Binary Data

For files or other arbitrary data, pass bytes directly and keep the decrypted result as bytes. Do not convert arbitrary binary data to text.

```ts
import { decrypt, encrypt } from 'doublesec';

const passphrase = crypto.getRandomValues(new Uint8Array(32)); // Persist securely and reuse for decryption.
const data = Uint8Array.of(0x00, 0x80, 0xff);

const ciphertext = await encrypt({ passphrase, data });
const recovered = await decrypt({ passphrase, data: ciphertext });
// recovered is Uint8Array [0, 128, 255]
```

### Convert Ciphertext To A String

Ciphertext is binary. Encode it as a Base64 string when a text representation of the ciphertext is needed, for instance to store it in a database, then decode it before decryption. Base64 is an encoding, not an additional form of encryption.

```ts
import {
  base64ToBytes,
  bytesToBase64,
  bytesToString,
  decrypt,
  encrypt,
  stringToBytes,
} from 'doublesec';

const passphrase = stringToBytes('replace with a strong passphrase');
const data = stringToBytes('A message to store');

const ciphertext = await encrypt({ passphrase, data });

const storedValue = bytesToBase64(ciphertext); // Save this string to the database.

const decodedCiphertext = base64ToBytes(storedValue); // Same bytes as ciphertext.

const decryptedBytes = await decrypt({ passphrase, data: decodedCiphertext });
const message = bytesToString(decryptedBytes);
```

### Errors and ciphertext size

`encrypt` and `decrypt` return promises and reject if their byte inputs are invalid or an operation fails. Decryption also rejects malformed or unsupported ciphertext and authentication failures, such as a wrong passphrase or altered data. Handle these errors at the point where you can report or recover from them; do not treat failed decryption as an empty message.

## Browser and security notes

The library uses native Web Crypto for AES-CTR and HMAC-SHA-512 when supported, and falls back to Noble implementations when those operations are unavailable or blocked. Scrypt, XSalsa20, and HMAC-SHA3-512 use Noble. Encryption requires `crypto.getRandomValues`; supported modern browsers and Node.js versions provide it.

TripleSec v4 uses a fixed scrypt cost for compatibility. Key derivation requires roughly 32 MiB of memory per concurrent operation, so avoid starting many encryptions or decryptions at once. Keep passphrases secret and available for future decryption. Encryption does not conceal the plaintext length.

The standalone browser bundle and demo can be opened locally without loading ES modules. For sensitive inputs, use a trusted local copy or HTTPS: a page delivered over plain HTTP can be altered before the encryption code runs.

## Compatibility

The tests use a [published Keybase v4 vector](https://github.com/keybase/go-triplesec/blob/master/spec/triplesec_v4.json) to verify byte-for-byte encryption and decryption with and without native browser crypto.
