/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
const NON_SECRET_PROPERTIES = new Set([
  '@context', 'id', 'type', 'controller',
  'publicKeyMultibase', 'maxCapabilityChainLength',
  'publicAlias', 'publicAliasTemplate'
]);

// pass `key` from a key `record`
export async function decryptKeySecrets({recordCipher, key} = {}) {
  // decrypt secrets
  const {encrypted: encryptedSecrets, ...rest} = key;
  const {secrets} = await recordCipher.decryptRecordSecrets({
    record: {encryptedSecrets}
  });
  // return new key object w/decrypted secrets
  return {...rest, ...secrets};
}

// pass `key` from a key `record`
export async function encryptKeySecrets({recordCipher, key} = {}) {
  if(key.encrypted !== undefined) {
    // should not happen; bad call
    throw new Error(
      'Could not encrypt key secrets; key secrets already encrypted.');
  }

  // get current wrap key ID
  if(!recordCipher.isSecretsEncryptionEnabled()) {
    // no KEK config; return early
    return key;
  }

  // separate record key's non-secret / secret properties
  const nonSecrets = new Map();
  const secrets = new Map();
  for(const prop in key) {
    const value = key[prop];
    if(NON_SECRET_PROPERTIES.has(prop)) {
      nonSecrets.set(prop, value);
      continue;
    }
    secrets.set(prop, value);
  }

  // encrypt key secrets
  const {encryptedSecrets} = await recordCipher.encryptRecordSecrets({
    record: {secrets}
  });

  // return new key object w/encrypted secrets
  return {
    ...Object.fromEntries(nonSecrets.entries()),
    encrypted: encryptedSecrets
  };
}
