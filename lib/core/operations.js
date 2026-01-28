/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
*/
import * as _asymmetricKey from './asymmetricKey.js';
import * as _hmacKey from './hmacKey.js';
import * as _keyAgreementKey from './keyAgreementKey.js';
import * as _wrapKey from './wrapKey.js';

const OPERATIONS = new Map([
  // asymmetric keys
  ['Ed25519VerificationKey2018', _asymmetricKey],
  ['Ed25519VerificationKey2020', _asymmetricKey],
  ['urn:webkms:multikey:Ed25519', _asymmetricKey],
  ['urn:webkms:multikey:P-256', _asymmetricKey],
  ['urn:webkms:multikey:P-384', _asymmetricKey],
  ['urn:webkms:multikey:P-521', _asymmetricKey],
  ['urn:webkms:multikey:BBS-BLS12-381-SHA-256', _asymmetricKey],
  ['urn:webkms:multikey:BBS-BLS12-381-SHAKE-256', _asymmetricKey],
  ['urn:webkms:multikey:Bls12381G2', _asymmetricKey],
  // key agreement keys
  ['X25519KeyAgreementKey2020', _keyAgreementKey],
  ['urn:webkms:multikey:X25519', _keyAgreementKey],
  ['urn:webkms:multikey:ECDH-P-256', _keyAgreementKey],
  ['urn:webkms:multikey:ECDH-P-384', _keyAgreementKey],
  ['urn:webkms:multikey:ECDH-P-521', _keyAgreementKey],
  // wrapping keys
  ['AesKeyWrappingKey2019', _wrapKey],
  // hmac keys
  ['Sha256HmacKey2019', _hmacKey],
]);

export function getKeyOp({name, type}) {
  const ops = OPERATIONS.get(type);
  if(!ops) {
    throw new Error(`Unknown key type "${type}".`);
  }
  const op = ops[name];
  if(!op) {
    throw new Error(`Unsupported operation "${name}" for key type "${type}".`);
  }
  return op;
}
