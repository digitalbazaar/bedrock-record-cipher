/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from 'node:crypto';

const SUPPORTED_KEY_TYPES = new Map([
  ['Sha256HmacKey2019', 'https://w3id.org/security/suites/hmac-2019/v1']
]);

/**
 * Generates a new HMAC key.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.type - A KEY_TYPE.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} An object containing `{key, keyDescription}`.
 */
export async function generateKey({keyId, type, controller} = {}) {
  const keyContextUrl = SUPPORTED_KEY_TYPES.get(type);
  if(!keyContextUrl) {
    throw new Error(`Unknown key type "${type}".`);
  }

  const key = {
    '@context': keyContextUrl,
    id: keyId,
    type,
    secret: Buffer.from(crypto.randomBytes(32)).toString('base64url')
  };

  const keyDescription = {
    '@context': keyContextUrl,
    id: keyId,
    type,
    controller
  };

  return {key, keyDescription};
}

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {object} options.key - The key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Contains `{signatureValue}`.
 */
export async function sign({key, operation}) {
  if(key.type !== 'Sha256HmacKey2019') {
    throw new Error(`Unknown key type "${key.type}".`);
  }
  const {verifyData} = operation;
  const signatureValue = await _hs256Sign({key, verifyData});
  return {signatureValue: Buffer.from(signatureValue).toString('base64url')};
}

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {object} options.key - The key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{verified}`.
 */
export async function verify({key, operation}) {
  if(key.type !== 'Sha256HmacKey2019') {
    throw new Error(`Unknown key type "${key.type}".`);
  }
  const {signatureValue, verifyData} = operation;
  const verified = await _hs256Verify({key, verifyData, signatureValue});
  return {verified};
}

async function _hs256Sign({key, verifyData}) {
  const secret = Buffer.from(key.secret, 'base64url');
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(Buffer.from(verifyData, 'base64url'));
  return hmac.digest();
}

async function _hs256Verify({key, verifyData, signatureValue}) {
  signatureValue = Buffer.from(signatureValue, 'base64url');
  const signatureCheck = await _hs256Sign({key, verifyData});
  return crypto.timingSafeEqual(signatureValue, signatureCheck);
}
