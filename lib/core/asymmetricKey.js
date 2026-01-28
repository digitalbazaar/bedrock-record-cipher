/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as bedrock from '@bedrock/core';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';

const {util: {BedrockError}} = bedrock;

const ED25519_2018_V1_URL =
  'https://w3id.org/security/suites/ed25519-2018/v1';
const ED25519_2020_V1_URL =
  'https://w3id.org/security/suites/ed25519-2020/v1';

/**
 * Generates a new asymmetric key pair.
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
  if(type.includes('Ed25519')) {
    keyPair = await Ed25519Multikey.generate({id: keyId});
  } else if(type.startsWith('urn:webkms:multikey:P-')) {
    const curve = type.slice('urn:webkms:multikey:'.length);
    keyPair = await EcdsaMultikey.generate({id: keyId, curve});
  } else if(type.startsWith('urn:webkms:multikey:BBS-') ||
    type === 'urn:webkms:multikey:Bls12381G2') {
    let algorithm = type.slice('urn:webkms:multikey:'.length);
    if(algorithm === 'Bls12381G2') {
      // default curve-as-algorithm to:
      algorithm = 'BBS-BLS12-381-SHA-256';
    }
    keyPair = await Bls12381Multikey.generateBbsKeyPair(
      {id: keyId, algorithm});
  } else {
    throw new BedrockError(`Unsupported key type "${type}".`, {
      name: 'NotSupportedError',
      details: {public: true, httpStatusCode: 400}
    });
  }

  // generate full key portion for internal record
  let key = await keyPair.export(
    {publicKey: true, secretKey: true, includeContext: true});
  key.type = type;

  // generate public key description
  let keyDescription = await keyPair.export({
    publicKey: true, includeContext: true
  });

  // perform transform for legacy key types
  if(type === 'Ed25519VerificationKey2020') {
    key = {
      '@context': ED25519_2020_V1_URL,
      id: key.id,
      type,
      privateKeyMultibase: key.secretKeyMultibase,
      publicKeyMultibase: key.publicKeyMultibase
    };
    keyDescription['@context'] = ED25519_2020_V1_URL;
    keyDescription.type = type;
  } else if(type === 'Ed25519VerificationKey2018') {
    key = {
      '@context': ED25519_2018_V1_URL,
      id: key.id,
      type,
      privateKeyBase58: _multibaseMultikeyToBase58(key.secretKeyMultibase),
      publicKeyBase58: _multibaseMultikeyToBase58(key.publicKeyMultibase)
    };
    keyDescription = {
      '@context': ED25519_2018_V1_URL,
      id: key.id,
      type,
      publicKeyBase58: key.publicKeyBase58,
      controller
    };
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
 * @param {object} options.key - The key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Contains `{signatureValue}`.
 */
export async function sign({key, operation}) {
  // prepare `key` for import
  const {type} = key;
  if(type.startsWith('urn:webkms:multikey:')) {
    // import key as a `Multikey`
    key = {...key, type: 'Multikey'};
  }

  let keyPair;
  if(type.startsWith('urn:webkms:multikey:P-')) {
    keyPair = await EcdsaMultikey.from(key);
  } else if(type.startsWith('urn:webkms:multikey:BBS-') ||
    type === 'urn:webkms:multikey:Bls12381G2') {
    keyPair = await Bls12381Multikey.from(key);
  } else {
    keyPair = await Ed25519Multikey.from(key);
  }

  const {sign} = keyPair.signer();
  const {verifyData} = operation;
  const signatureBytes = await sign({
    data: Buffer.from(verifyData, 'base64url')
  });
  return {signatureValue: Buffer.from(signatureBytes).toString('base64url')};
}

function _multibaseMultikeyToBase58(mb) {
  // special transform for Ed25519 secret or public multibase multikey values
  const mk = base58.decode(mb.slice(1));
  return base58.encode(mk.slice(2));
}
