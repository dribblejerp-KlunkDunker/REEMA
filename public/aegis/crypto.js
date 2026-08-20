/**
 * SOVEREIGN // AEGIS — Cryptographic Engine (AegisCrypto)
 * WebCrypto ECDSA P-256, did:key multicodec/base58, W3C JSON-LD Verifiable Credentials,
 * Deterministic canonicalization, Base64url, and SHA-256 hashing.
 */

// Base58BTC Alphabet
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Native or global WebCrypto SubtleCrypto reference resolver
 */
function getSubtleCrypto() {
  if (typeof globalThis !== 'undefined') {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      return globalThis.crypto.subtle;
    }
  }
  throw new Error('[AegisCrypto] WebCrypto SubtleCrypto API is not available in the current environment.');
}

/**
 * Native or global Crypto reference resolver
 */
function getCrypto() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    return globalThis.crypto;
  }
  throw new Error('[AegisCrypto] Crypto API is not available in the current environment.');
}

export class AegisCrypto {
  /**
   * Generates a new cryptographic ECDSA P-256 keypair and derives its did:key identifier.
   *
   * The private key is NON-EXTRACTABLE by default. It can sign, but its `d` parameter
   * can never be read back out — not by this code, and not by injected script. This is
   * the difference between "an attacker who achieves XSS can read your journal" and
   * "an attacker who achieves XSS can permanently impersonate your DID".
   *
   * Pass `{ extractable: true }` only where the private JWK genuinely must leave the
   * keystore (offline test vectors, an explicit user-initiated key backup). Doing so in
   * application code re-opens the key-theft path.
   *
   * @param {{extractable?: boolean}} [options]
   * @returns {Promise<{
   *   keyPair: CryptoKeyPair,
   *   did: string,
   *   publicKeyJwk: JsonWebKey,
   *   privateKeyJwk: JsonWebKey|null,
   *   extractable: boolean,
   *   fingerprint: string
   * }>}
   */
  static async generateKeyPair(options = {}) {
    const subtle = getSubtleCrypto();
    const extractable = options.extractable === true;

    const keyPair = await subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      extractable,
      ['sign', 'verify']
    );

    // The public half is always exportable — it is published in the DID document.
    const publicKeyJwk = await subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = extractable
      ? await subtle.exportKey('jwk', keyPair.privateKey)
      : null;

    const did = this.jwkToDidKey(publicKeyJwk);
    const fingerprint = await this.computeHash(JSON.stringify(publicKeyJwk));

    return {
      keyPair,
      did,
      publicKeyJwk,
      privateKeyJwk,
      extractable,
      fingerprint: fingerprint.slice(0, 16)
    };
  }

  /**
   * Signs an arbitrary statement or payload object using an ECDSA P-256 private key.
   * @param {CryptoKey|JsonWebKey} privateKey - CryptoKey instance or JWK
   * @param {Object|string} statementObj - The content to sign
   * @returns {Promise<string>} Base64url signature string
   */
  static async signStatement(privateKey, statementObj) {
    const subtle = getSubtleCrypto();
    let signingKey = privateKey;

    if (!(signingKey instanceof CryptoKey)) {
      signingKey = await subtle.importKey(
        'jwk',
        privateKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
      );
    }

    const canonicalStr = typeof statementObj === 'string'
      ? statementObj
      : this.canonicalize(statementObj);

    const dataBuffer = new TextEncoder().encode(canonicalStr);

    const signatureBuffer = await subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      signingKey,
      dataBuffer
    );

    return this.base64UrlEncode(new Uint8Array(signatureBuffer));
  }

  /**
   * Verifies an ECDSA P-256 digital signature against a statement and public key.
   * @param {CryptoKey|JsonWebKey} publicKey - CryptoKey instance or JWK
   * @param {Object|string} statementObj - The original content payload
   * @param {string} signature - Base64url signature string
   * @returns {Promise<boolean>}
   */
  static async verifyStatement(publicKey, statementObj, signature) {
    try {
      const subtle = getSubtleCrypto();
      let verifyKey = publicKey;

      if (!(verifyKey instanceof CryptoKey)) {
        verifyKey = await subtle.importKey(
          'jwk',
          publicKey,
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['verify']
        );
      }

      const canonicalStr = typeof statementObj === 'string'
        ? statementObj
        : this.canonicalize(statementObj);

      const dataBuffer = new TextEncoder().encode(canonicalStr);
      const sigBuffer = this.base64UrlDecode(signature);

      const isValid = await subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' }
        },
        verifyKey,
        sigBuffer,
        dataBuffer
      );

      return Boolean(isValid);
    } catch (err) {
      console.warn('[AegisCrypto] Signature verification failed with error:', err);
      return false;
    }
  }

  /**
   * Formats a statement and signature into a W3C-compliant JSON-LD Verifiable Credential.
   * @param {string} did - Issuer decentralized identifier (did:key:...)
   * @param {JsonWebKey} publicKeyJwk - Issuer public key in JWK format
   * @param {Object} statementObj - Credential subject claims
   * @param {string} signature - Base64url signature over statementObj
   * @returns {Object} Standard W3C JSON-LD Verifiable Credential object
   */
  static exportVerifiableCredential(did, publicKeyJwk, statementObj, signature) {
    const issuanceDate = new Date().toISOString();
    const credId = `urn:uuid:${this.generateUUID()}`;

    return {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
        'https://sovereign-aegis.org/contexts/epistemic-v1.jsonld'
      ],
      id: credId,
      type: ['VerifiableCredential', 'EpistemicAttestationCredential'],
      issuer: did,
      issuanceDate,
      credentialSubject: {
        id: did,
        ...statementObj
      },
      proof: {
        type: 'JsonWebSignature2020',
        created: issuanceDate,
        proofPurpose: 'assertionMethod',
        verificationMethod: `${did}#${did.slice(-8)}`,
        jws: signature
      }
    };
  }

  /**
   * Computes a SHA-256 hash of any string, Uint8Array or object.
   * @param {string|Uint8Array|ArrayBuffer|Object} content 
   * @returns {Promise<string>} 64-character lowercase hexadecimal hash
   */
  static async computeHash(content) {
    const subtle = getSubtleCrypto();
    let dataBuffer;

    if (typeof content === 'string') {
      dataBuffer = new TextEncoder().encode(content);
    } else if (content instanceof Uint8Array || content instanceof ArrayBuffer) {
      dataBuffer = content;
    } else if (content && typeof content === 'object') {
      dataBuffer = new TextEncoder().encode(this.canonicalize(content));
    } else {
      dataBuffer = new TextEncoder().encode(String(content));
    }

    const digestBuffer = await subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(digestBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generates cryptographically secure random entropy formatted as a hex string.
   * @param {number} [byteLength=16] 
   * @returns {string} Hex string
   */
  static getRandomEntropy(byteLength = 16) {
    const cryptoObj = getCrypto();
    const bytes = new Uint8Array(byteLength);
    cryptoObj.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generates a cryptographically secure UUID v4 string.
   * @returns {string} UUID v4
   */
  static generateUUID() {
    const cryptoObj = getCrypto();
    if (typeof cryptoObj.randomUUID === 'function') {
      return cryptoObj.randomUUID();
    }

    const bytes = new Uint8Array(16);
    cryptoObj.getRandomValues(bytes);

    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 10xx

    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  /**
   * Derives a standard W3C did:key string from a JWK public key.
   * Uses Multicodec code 0x1200 (p256-pub) with Base58BTC encoding prefixed with 'z'.
   * @param {JsonWebKey} jwk - JWK containing crv: 'P-256', kty: 'EC', x, y
   * @returns {string} e.g. 'did:key:zDnae...'
   */
  static jwkToDidKey(jwk) {
    if (!jwk || !jwk.x || !jwk.y) {
      throw new Error('[AegisCrypto] Invalid JWK public key coordinates.');
    }

    const xBytes = this.base64UrlDecode(jwk.x);
    const yBytes = this.base64UrlDecode(jwk.y);

    // Compressed P-256 public key (33 bytes)
    // Prefix: 0x02 if Y is even, 0x03 if Y is odd
    const isYEven = (yBytes[yBytes.length - 1] % 2) === 0;
    const prefix = isYEven ? 0x02 : 0x03;

    const compressedKey = new Uint8Array(33);
    compressedKey[0] = prefix;
    compressedKey.set(xBytes, 1);

    // Multicodec for P-256 public key: 0x1200 (varint representation: 0x80, 0x24)
    const multicodec = new Uint8Array([0x80, 0x24]);
    const didBytes = new Uint8Array(multicodec.length + compressedKey.length);
    didBytes.set(multicodec, 0);
    didBytes.set(compressedKey, multicodec.length);

    // Base58BTC encoding prefixed with 'z'
    return `did:key:z${this.base58Encode(didBytes)}`;
  }

  /**
   * Canonicalizes an object into a deterministic JSON string with recursively sorted keys.
   * @param {*} obj 
   * @returns {string}
   */
  static canonicalize(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }

    if (Array.isArray(obj)) {
      return '[' + obj.map(item => this.canonicalize(item)).join(',') + ']';
    }

    const sortedKeys = Object.keys(obj).sort();
    const parts = [];

    for (const key of sortedKeys) {
      const val = obj[key];
      if (val !== undefined) {
        parts.push(JSON.stringify(key) + ':' + this.canonicalize(val));
      }
    }

    return '{' + parts.join(',') + '}';
  }

  /**
   * Base64url encoder (RFC 4648 §5)
   * @param {Uint8Array|ArrayBuffer} buffer 
   * @returns {string}
   */
  static base64UrlEncode(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    
    // In Node.js or browser with btoa
    let base64 = '';
    if (typeof btoa === 'function') {
      base64 = btoa(binary);
    } else if (typeof Buffer !== 'undefined') {
      base64 = Buffer.from(bytes).toString('base64');
    } else {
      throw new Error('[AegisCrypto] No Base64 encoder available.');
    }

    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Base64url decoder (RFC 4648 §5)
   * @param {string} str 
   * @returns {Uint8Array}
   */
  static base64UrlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }

    if (typeof atob === 'function') {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } else if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64, 'base64'));
    } else {
      throw new Error('[AegisCrypto] No Base64 decoder available.');
    }
  }

  /**
   * Base58BTC encoder
   * @param {Uint8Array} bytes 
   * @returns {string}
   */
  static base58Encode(bytes) {
    if (!bytes || bytes.length === 0) return '';

    // Count leading zeros
    let zeroes = 0;
    while (zeroes < bytes.length && bytes[zeroes] === 0) {
      zeroes++;
    }

    // Allocate enough space for output
    const size = ((bytes.length - zeroes) * 138 / 100 + 1) | 0;
    const b58 = new Uint8Array(size);

    let length = 0;
    for (let i = zeroes; i < bytes.length; i++) {
      let carry = bytes[i];
      let j = 0;
      for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
        carry += (b58[k] << 8);
        b58[k] = carry % 58;
        carry = (carry / 58) | 0;
      }
      length = j;
    }

    // Skip leading zeroes in b58
    let it = size - length;
    while (it < size && b58[it] === 0) {
      it++;
    }

    let str = '1'.repeat(zeroes);
    for (; it < size; ++it) {
      str += BASE58_ALPHABET.charAt(b58[it]);
    }

    return str;
  }

  /**
   * Base58BTC decoder
   * @param {string} str 
   * @returns {Uint8Array}
   */
  static base58Decode(str) {
    if (!str || str.length === 0) return new Uint8Array(0);

    let zeroes = 0;
    while (zeroes < str.length && str.charAt(zeroes) === '1') {
      zeroes++;
    }

    const size = ((str.length - zeroes) * 733 / 1000 + 1) | 0;
    const bytes = new Uint8Array(size);

    let length = 0;
    for (let i = zeroes; i < str.length; i++) {
      const c = str.charAt(i);
      const value = BASE58_ALPHABET.indexOf(c);
      if (value === -1) {
        throw new Error(`[AegisCrypto] Non-base58 character: ${c}`);
      }

      let carry = value;
      let j = 0;
      for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
        carry += 58 * bytes[k];
        bytes[k] = carry % 256;
        carry = (carry / 256) | 0;
      }
      length = j;
    }

    let it = size - length;
    while (it < size && bytes[it] === 0) {
      it++;
    }

    const result = new Uint8Array(zeroes + (size - it));
    result.fill(0, 0, zeroes);
    result.set(bytes.subarray(it), zeroes);
    return result;
  }
}
