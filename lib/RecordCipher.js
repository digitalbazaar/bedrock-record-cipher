/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {decode, encode} from 'cborg';
import {generalDecrypt, GeneralEncrypt} from 'jose';

const {util: {BedrockError}} = bedrock;

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

/* Multikey registry IDs and encoded header values
aes-256 | 0xa2 | 256-bit AES symmetric key
*/
const SUPPORTED_KEK_TYPES = new Map([
  ['aes-256', {header: new Uint8Array([0xa2, 0x01]), size: 32}]
]);

export class RecordCipher {
  constructor({currentKekId, keks, encoding} = {}) {
    this.keks = keks;
    this.encoding = encoding;
    this.setCurrentKek({id: currentKekId});
  }

  /**
   * Decrypts `encryptedSecrets`, if found, in a record.
   *
   * @param {object} options - The options to use.
   * @param {object} options.record - The record with optional
   *   `encryptedSecrets` to decrypt.
   *
   * @returns {Promise<object>} An object with `secrets` instead of
   *   `encryptedSecrets`.
   */
  async decryptRecordSecrets({record} = {}) {
    if(record.encryptedSecrets === undefined) {
      // nothing to decrypt, return early
      return record;
    }

    try {
      // decrypt secrets
      const {encryptedSecrets, ...rest} = record;
      const {kekId, jwe, encoding = this.encoding} = encryptedSecrets;
      const secretKey = await this.getKek({id: kekId});
      const {plaintext} = await generalDecrypt(jwe, secretKey);
      const secrets = encoding === 'cbor' ?
        _cborDecodeSecrets(plaintext) : _jsonDecodeSecrets(plaintext);

      // new record object w/decrypted secrets
      return {...rest, secrets};
    } catch(cause) {
      throw new BedrockError('Could not decrypt record secrets.', {
        name: 'OperationError',
        cause,
        details: {
          public: true,
          httpStatusCode: 500
        }
      });
    }
  }

  /**
   * Encrypts `secrets`, if found, in a record.
   *
   * @param {object} options - The options to use.
   * @param {object} options.record - The record with optional `secrets` to
   *   encrypt.
   *
   * @returns {Promise<object>} An object with `encryptedSecrets` instead of
   *   `secrets`.
   */
  async encryptRecordSecrets({record} = {}) {
    if(record.encryptedSecrets !== undefined) {
      // should not happen; bad call
      throw new Error(
        'Could not encrypt record secrets; secrets already encrypted.');
    }

    try {
      // get current wrap key ID
      const {currentKekId: kekId, encoding} = this;
      if(!kekId) {
        // no KEK config; return early
        return record;
      }

      // encrypt secrets
      const {secrets, ...nonSecrets} = record;
      const plaintext = encoding === 'cbor' ?
        _cborEncodeSecrets(secrets) : _jsonEncodeSecrets(secrets);
      const secretKey = await this.getKek({id: kekId});
      const jwe = await new GeneralEncrypt(plaintext)
        .setProtectedHeader({enc: 'A256GCM'})
        .addRecipient(secretKey)
        .setUnprotectedHeader({alg: 'A256KW', kid: kekId})
        .encrypt();

      // return new record w/encrypted secrets
      return {
        ...nonSecrets,
        encryptedSecrets: {kekId, jwe, encoding}
      };
    } catch(cause) {
      throw new BedrockError('Could not encrypt record secrets.', {
        name: 'OperationError',
        cause,
        details: {
          public: true,
          httpStatusCode: 500
        }
      });
    }
  }

  addKek({id, secretKey, secretKeyMultibase} = {}) {
    if(this.keks.has(id)) {
      throw new BedrockError(`Key encryption key "${id}" already set.`, {
        name: 'ConstraintsError',
        details: {
          public: true,
          httpStatusCode: 409
        }
      });
    }
    if(secretKey) {
      this.keks.set(id, secretKey);
    } else {
      this.keks.set(id, _loadKek(secretKeyMultibase));
    }
  }

  async getKek({id} = {}) {
    const secretKey = this.keks.get(id);
    if(secretKey) {
      return secretKey;
    }
    throw new BedrockError(`Key encryption key "${id}" not found.`, {
      name: 'NotFoundError',
      details: {
        public: true,
        httpStatusCode: 400
      }
    });
  }

  isSecretsEncryptionEnabled() {
    return this.currentKekId !== null;
  }

  setCurrentKek({id} = {}) {
    if(id !== null) {
      // ensure secret key exists
      if(!this.keks.has(id)) {
        throw new BedrockError(`Key encryption key "${id}" not found.`, {
          name: 'NotFoundError',
          details: {
            public: true,
            httpStatusCode: 400
          }
        });
      }
    }
    this.currentKekId = id;
  }

  /**
   * Creates a `RecordCipher` instance for encrypting and/or decrypting
   * record `secrets`. The default encoding mode for the `secrets` is `cbor`,
   * which supports any binary subfields present in `secrets`. The encoding
   * can alternatively be set to `json` for backwards compatiblity with
   * modules that previously encoded using JSON, not CBOR.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.currentKekId] - The ID of the KEK to use for
   *   new encryptions; may be set to `null` to disable encryption; if not
   *   set, it will be automatically set to the first KEK ID in the `keks`
   *   array if it is not empty (otherwise it will be set to `null`).
   * @param {Array} [options.keks=[]] - An array of objects, each with an `id`
   *   `id` value for a KEK to use for encryption and decryption as well as its
   *   `secretKeyMultibase` including a base64url-encoded AES-256 key value.
   * @param {string} [options.encoding='cbor'] - The encoding to use for the
   *   values found in `secrets`; either `cbor` or `json`, `cbor` supports
   *   binary values and `json` does not and is only provided for backwards
   *   compatibility and should not be used with new applications).
   *
   * @returns {Promise<RecordCipher>} A new RecordCipher instance based on
   *   the given options; if `currentKekId` is specified as `null` then this
   *   instance will return `false` from `isSecretsEncryptionEnabled()`.
   */
  static async create({currentKekId, keks = [], encoding = 'cbor'} = {}) {
    if(!(currentKekId === undefined || currentKekId === null ||
      typeof currentKekId !== 'string')) {
      throw new TypeError('"currentKekId" must be a string or null.');
    }
    if(!Array.isArray(keks)) {
      throw new TypeError('"keks" must be an array.');
    }
    if(!(encoding === 'cbor' || encoding === 'json')) {
      throw new Error('"encoding" must be "cbor" or "json".');
    }

    const recordCipher = new RecordCipher({
      currentKekId: null, keks: new Map(), encoding
    });

    // add all KEKs in `keks`
    let firstId;
    for(const key of keks) {
      if(!(key.id && typeof key.id === 'string')) {
        throw new BedrockError(
          'Invalid key encryption key configuration; ' +
          'key "id" must be a string.', {
            name: 'DataError',
            details: {
              public: true,
              httpStatusCode: 400
            }
          });
      }
      if(firstId === undefined) {
        firstId = key.id;
      }
      recordCipher.addKek(key);
    }

    if(currentKekId !== null) {
      recordCipher.setCurrentKek({id: currentKekId ?? firstId ?? null});
    }

    return recordCipher;
  }
}

function _cborDecodeSecrets(plaintext) {
  const decoded = decode(plaintext);
  // convert Uint8Arrays to Buffers for compatibility
  for(const [key, value] of Object.entries(decoded)) {
    decoded[key] = value instanceof Uint8Array ? Buffer.from(value) : value;
  }
  return decoded;
}

function _cborEncodeSecrets(secrets) {
  return encode(secrets);
}

function _jsonDecodeSecrets(plaintext) {
  return JSON.parse(TEXT_DECODER.decode(plaintext));
}

function _jsonEncodeSecrets(secrets) {
  const obj = secrets instanceof Map ?
    Object.fromEntries(secrets.entries()) : secrets;
  return TEXT_ENCODER.encode(JSON.stringify(obj));
}

function _loadKek(secretKeyMultibase) {
  if(!secretKeyMultibase?.startsWith('u')) {
    throw new BedrockError(
      'Unsupported multibase header; ' +
      '"u" for base64url-encoding must be used.', {
        name: 'NotSupportedError',
        details: {
          public: true,
          httpStatusCode: 400
        }
      });
  }

  // check multikey header
  let keyType;
  let secretKey;
  const multikey = Buffer.from(secretKeyMultibase.slice(1), 'base64url');
  for(const [type, {header, size}] of SUPPORTED_KEK_TYPES) {
    if(multikey[0] === header[0] && multikey[1] === header[1]) {
      keyType = type;
      if(multikey.length !== (2 + size)) {
        // intentionally do not report what was detected because a
        // misconfigured secret could have its first two bytes revealed
        throw new BedrockError(
          'Incorrect multikey size or invalid multikey header.', {
            name: 'DataError',
            details: {
              public: true,
              httpStatusCode: 400
            }
          });
      }
      secretKey = multikey.subarray(2);
      break;
    }
  }
  if(keyType === undefined) {
    throw new BedrockError(
      'Unsupported multikey type; only AES-256 is supported.', {
        name: 'NotSupportedError',
        details: {
          public: true,
          httpStatusCode: 400
        }
      });
  }

  return secretKey;
}
