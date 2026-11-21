import { bytesToString, decrypt, encrypt, stringToBytes } from '../src/index.js';

const form = document.querySelector<HTMLFormElement>('form')!;
const password = document.querySelector<HTMLInputElement>('#password')!;
const input = document.querySelector<HTMLTextAreaElement>('#input')!;
const output = document.querySelector<HTMLTextAreaElement>('#output')!;
const status = document.querySelector<HTMLParagraphElement>('#status')!;
const controls = document.querySelector<HTMLFieldSetElement>('fieldset')!;

function fromHex(value: string): Uint8Array {
  const hex = value.replace(/\s/g, '');
  if (!/^(?:[\da-f]{2})+$/i.test(hex)) throw new Error('Enter a ciphertext in hexadecimal.');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (controls.disabled) return;
  const encrypting = event.submitter?.getAttribute('value') !== 'decrypt';
  controls.disabled = true;
  status.textContent = encrypting ? 'Encrypting…' : 'Decrypting…';
  output.value = '';
  const passphrase = stringToBytes(password.value);
  try {
    // Let the browser paint the busy state before starting scrypt.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    if (encrypting) {
      const plaintext = stringToBytes(input.value);
      try {
        const result = await encrypt({ passphrase, data: plaintext });
        output.value = Array.from(result, (byte) => byte.toString(16).padStart(2, '0')).join('');
      } finally {
        plaintext.fill(0);
      }
    } else {
      const plaintext = await decrypt({ passphrase, data: fromHex(input.value) });
      try {
        output.value = bytesToString(plaintext);
      } finally {
        plaintext.fill(0);
      }
    }
    status.textContent = encrypting ? 'Encrypted to hexadecimal.' : 'Decrypted to text.';
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : 'Operation failed.';
  } finally {
    passphrase.fill(0);
    controls.disabled = false;
  }
});
