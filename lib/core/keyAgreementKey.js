/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as bedrock from '@bedrock/core';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {
  X25519KeyAgreementKey2020
} from '@digitalbazaar/x25519-key-agreement-key-2020';

const {util: {BedrockError}} = bedrock;

const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';

const SUPPORTED_MULTIKEY_TYPES = new Map([
  ['ec01', 'urn:webkms:multikey:X25519'],
  ['8024', 'urn:webkms:multikey:ECDH-P-256'],
  ['8124', 'urn:webkms:multikey:ECDH-P-384'],
  ['8224', 'urn:webkms:multikey:ECDH-P-521']
]);

/**
 * Generates a new key agreement key pair.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.type - The key type.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} An object containing `{key, keyDescription}`.
 */
export async function generateKey({keyId, type, controller} = {}) {
  let keyPair;
  if(type.startsWith('urn:webkms:multikey:ECDH-P-')) {
    const curve = type.slice('urn:webkms:multikey:ECDH-'.length);
    keyPair = await EcdsaMultikey.generate({
      id: keyId, curve, keyAgreement: true
    });
  } else if(type.includes('X25519')) {
    keyPair = await X25519KeyAgreementKey2020.generate({id: keyId});
  } else {
    throw new BedrockError(`Unsupported key type "${type}".`, {
      name: 'NotSupportedError',
      details: {public: true, httpStatusCode: 400}
    });
  }

  // generate full key portion for internal record
  const key = await keyPair.export(
    {publicKey: true, privateKey: true, secretKey: true, includeContext: true});
  key.type = type;

  // generate public key description
  let keyDescription = await keyPair.export({
    publicKey: true, includeContext: true
  });

  // special handling for `X25519` Multikey
  if(type == 'urn:webkms:multikey:X25519') {
    key['@context'] = MULTIKEY_CONTEXT_V1_URL;
    key.secretKeyMultibase = key.privateKeyMultibase;
    delete key.privateKeyMultibase;
    keyDescription['@context'] = MULTIKEY_CONTEXT_V1_URL;
    keyDescription.type = 'Multikey';
  }

  // consistently order key description properties
  {
    const {
      ['@context']: context, id, type, ...rest
    } = keyDescription;
    keyDescription = {
      '@context': context, id, type, ...rest, controller
    };
  }

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
 * @param {object} options.key - Exported key pair record, loaded from storage.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<{secret: string}>} Resolves with the derived secret.
 */
export async function deriveSecret({key, operation}) {
  const {publicKey} = operation;
  const type = publicKey.type === 'Multikey' ?
    _parseMultikey(publicKey.publicKeyMultibase) : publicKey.type;
  if(type !== key.type) {
    throw Error(
      `The given public key type "${type}" does not match the ` +
      `key agreement key's type "${key.type}".`);
  }

  let keyPair;
  if(key.type.includes('X25519')) {
    // special handling for `X25519` Multikey
    if(type === 'urn:webkms:multikey:X25519') {
      key = {
        ...key,
        privateKeyMultibase: key.secretKeyMultibase
      };
    }
    keyPair = await X25519KeyAgreementKey2020.from(key);
  } else {
    // import `key` as a `Multikey`
    keyPair = await EcdsaMultikey.from(
      {...key, type: 'Multikey'}, {keyAgreement: true});
  }

  const secret = await keyPair.deriveSecret({publicKey});
  return {secret: Buffer.from(secret).toString('base64url')};
}

function _parseMultikey(mb) {
  let multikey;
  const mbHeader = mb?.[0];
  if(mbHeader === 'z') {
    multikey = base58.decode(mb.slice(1));
  } else if(mbHeader === 'u') {
    multikey = Buffer.from(mb.slice(1), 'base64url');
  } else {
    throw new BedrockError(`Unsupported multibase header "${mbHeader}".`, {
      name: 'NotSupportedError',
      details: {public: true, httpStatusCode: 400}
    });
  }

  const header = Buffer.from(multikey.subarray(0, 2)).toString('hex');
  const type = SUPPORTED_MULTIKEY_TYPES.get(header);
  if(!type) {
    throw new BedrockError(`Unsupported multikey header "${header}".`, {
      name: 'NotSupportedError',
      details: {public: true, httpStatusCode: 400}
    });
  }

  return type;
}
