/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brPackageManager from '@bedrock/package-manager';
import {Core} from './core/index.js';
import {createKeyStorage} from './storage/index.js';
import {logger} from './logger.js';
import {RecordCipher} from './RecordCipher.js';

// load config defaults
import './config.js';

let CORE;
let KEY_STORAGE;
let KEY_RECORD_CIPHER;

bedrock.events.on('bedrock.init', async () => {
  // create security module core and key record cipher/storage singletons
  CORE = new Core();
  KEY_RECORD_CIPHER = _createKeyRecordCipher();
  KEY_STORAGE = await createKeyStorage({
    collectionName: 'ssm', recordCipher: KEY_RECORD_CIPHER
  });

  return brPackageManager.register({
    alias: 'ssm-v1',
    packageName: '@bedrock/ssm-mongodb',
    type: 'webkms-module'
  });
});

/**
 * @module bedrock-ssm-mongodb
 */

/**
 * Generates a new key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Key information `{keyId, keyDescription}`.
 */
export async function generateKey({keyId, controller, operation}) {
  const {key, keyDescription} = await CORE.generateKey({
    keyId, controller, operation
  });
  await KEY_STORAGE.insert({key});

  return {keyId, keyDescription};
}

/**
 * Gets the number of keys in a given keystore.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keystoreId - The ID of the keystore.
 *
 * @returns {Promise<object>} Key count information.
 */
export async function getKeyCount({keystoreId} = {}) {
  return KEY_STORAGE.getCount({keystoreId});
}

/**
 * Gets the key description (no private key material) for the given key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} Key information.
 */
export async function getKeyDescription({keyId, controller} = {}) {
  const {key} = await KEY_STORAGE.get({id: keyId});
  return CORE.getKeyDescription({key, controller});
}

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{wrappedKey}`.
 */
export async function wrapKey({keyId, operation, zcapInvocation}) {
  const {key} = await KEY_STORAGE.get({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
  return CORE.wrapKey({key, operation});
}

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{unwrappedKey}`.
 */
export async function unwrapKey({keyId, operation, zcapInvocation}) {
  const {key} = await KEY_STORAGE.get({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
  return CORE.unwrapKey({key, operation});
}

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{signatureValue}`.
 */
export async function sign({keyId, operation, zcapInvocation}) {
  const {key} = await KEY_STORAGE.get({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
  return CORE.sign({key, operation});
}

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{verified}`.
 */
export async function verify({keyId, operation, zcapInvocation}) {
  const {key} = await KEY_STORAGE.get({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
  return CORE.verify({key, operation});
}

/**
* Derives a shared secret via the given peer public key, typically for use
* as one parameter for computing a shared key. It should not be used as
* a shared key itself, but rather input into a key derivation function (KDF)
* to produce a shared key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{secret}`.
 */
export async function deriveSecret({keyId, operation, zcapInvocation}) {
  const {key} = await KEY_STORAGE.get({id: keyId});
  _checkZcapInvocationRules({key, zcapInvocation});
  return CORE.deriveSecret({key, operation});
}

function _checkZcapInvocationRules({key, zcapInvocation}) {
  // operation not invoked via zcap
  if(!zcapInvocation) {
    return;
  }
  // no extra zcap invocation restrictions on the key
  if(key.maxCapabilityChainLength === undefined) {
    return;
  }
  // ensure zcap invocation capability change length does not exceed the
  // rules from the key record
  if(zcapInvocation.dereferencedChain.length > key.maxCapabilityChainLength) {
    throw new Error(
      'Maximum zcap invocation capability chain length ' +
      `(${key.maxCapabilityChainLength}) exceeded.`);
  }
}

// exported for testing purposes only
export async function _createKeyRecordCipher() {
  KEY_RECORD_CIPHER = await RecordCipher.fromConfig({
    config: bedrock.config['ssm-mongodb'].keyRecordEncryption,
    encoding: 'json'
  });
  const status = KEY_RECORD_CIPHER.isSecretsEncryptionEnabled() ?
    'enabled' : 'disabled';
  logger.info(`Key record encryption is ${status}.`);
  if(KEY_STORAGE) {
    // replace instance in key storage to enable testing different configs
    KEY_STORAGE.recordCipher = KEY_RECORD_CIPHER;
  }
  return KEY_RECORD_CIPHER;
}
