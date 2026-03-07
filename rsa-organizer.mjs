/**
 * rsa-organizer.mjs
 * ==================
 * Hackathon - Security & Privacy - UPF 2025-26
 *
 * Handles RSA key generation, encryption and decryption of the auction
 * organizer's personal data (e.g. DNI) BEFORE it is published on-chain.
 *
 * WHY RSA HERE?
 *   Smart contracts are fully public - every byte stored on-chain is
 *   readable by anyone. RSA-OAEP ensures:
 *     - The ciphertext stored on-chain reveals nothing about the plaintext.
 *     - Only the organizer (private key holder) can decrypt it.
 *     - The public key (n, e) stored on-chain lets anyone verify provenance.
 *
 * USAGE
 * -----
 *   node rsa-organizer.mjs generate-keys
 *   node rsa-organizer.mjs encrypt "12345678A"
 *   node rsa-organizer.mjs decrypt "0xabc123..."
 *   node rsa-organizer.mjs pubkey-components
 *
 * REQUIREMENTS: Node.js >= 18 (built-in crypto module, no npm needed)
 */

import crypto from 'crypto';
import fs     from 'fs';
import path   from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KEYS_DIR  = path.join(__dirname, 'keys');
const PRIV_PATH = path.join(KEYS_DIR, 'organizer_private.pem');
const PUB_PATH  = path.join(KEYS_DIR, 'organizer_public.pem');

// ─── Key Generation ───────────────────────────────────────────────────────────

function generateKeys() {
  fs.mkdirSync(KEYS_DIR, { recursive: true });

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(PRIV_PATH, privateKey, { mode: 0o600 }); // owner-read only
  fs.writeFileSync(PUB_PATH,  publicKey);

  console.log('Keys generated:');
  console.log('  Private key ->', PRIV_PATH, ' (keep SECRET, never share)');
  console.log('  Public  key ->', PUB_PATH);
}

// ─── Load helpers ─────────────────────────────────────────────────────────────

function loadPublicKey() {
  if (!fs.existsSync(PUB_PATH))
    throw new Error('Public key not found. Run: node rsa-organizer.mjs generate-keys');
  return crypto.createPublicKey(fs.readFileSync(PUB_PATH, 'utf8'));
}

function loadPrivateKey() {
  if (!fs.existsSync(PRIV_PATH))
    throw new Error('Private key not found. Run: node rsa-organizer.mjs generate-keys');
  return crypto.createPrivateKey(fs.readFileSync(PRIV_PATH, 'utf8'));
}

// ─── Encrypt ──────────────────────────────────────────────────────────────────

function encryptData(plaintext) {
  const pub    = loadPublicKey();
  const cipher = crypto.publicEncrypt(
    { key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(plaintext, 'utf8')
  );
  const hex = '0x' + cipher.toString('hex');
  console.log('Encrypted ciphertext (hex):');
  console.log(hex);
  console.log('\nPaste this into the encryptedOrganizerData constructor field.');
  return hex;
}

// ─── Decrypt ──────────────────────────────────────────────────────────────────

function decryptData(hexCipher) {
  const priv  = loadPrivateKey();
  const bytes = Buffer.from(hexCipher.replace(/^0x/, ''), 'hex');
  const plain = crypto.privateDecrypt(
    { key: priv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    bytes
  );
  const text = plain.toString('utf8');
  console.log('Decrypted plaintext:');
  console.log(text);
  return text;
}

// ─── Public key components ────────────────────────────────────────────────────

function pubkeyComponents() {
  const pub = loadPublicKey();
  const jwk = pub.export({ format: 'jwk' });

  const b64urlToHex = s =>
    Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex');

  const nHex = b64urlToHex(jwk.n);
  const eHex = b64urlToHex(jwk.e);

  console.log('RSA Public Key Components (for smart contract constructor):');
  console.log('  n (modulus hex) :', nHex);
  console.log('  e (exponent hex):', eHex);
  return { n: nHex, e: eHex };
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

const [,, command, arg] = process.argv;

switch (command) {
  case 'generate-keys':      generateKeys();        break;
  case 'encrypt':
    if (!arg) { console.error('Usage: node rsa-organizer.mjs encrypt "<text>"'); process.exit(1); }
    encryptData(arg);
    break;
  case 'decrypt':
    if (!arg) { console.error('Usage: node rsa-organizer.mjs decrypt "<0xhex>"'); process.exit(1); }
    decryptData(arg);
    break;
  case 'pubkey-components':  pubkeyComponents();    break;
  default:
    console.log(`
Hash Auction - RSA Helper
Commands:
  generate-keys              Generate 2048-bit RSA key pair -> ./keys/
  encrypt "<text>"           Encrypt personal data (e.g. DNI)
  decrypt "<0xhex>"          Decrypt ciphertext with private key
  pubkey-components          Print n and e for the contract constructor
    `);
}

export { generateKeys, encryptData, decryptData, pubkeyComponents };
