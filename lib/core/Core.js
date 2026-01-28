/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
*/
import assert from 'assert-plus';
import {getKeyOp} from './operations.js';
import {parseTemplate} from 'url-template';

export class Core {
  constructor() {}

  /**
   * Generates a new key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The key ID to use.
   * @param {string} options.controller - The key controller.
   * @param {object} options.operation - The KMS operation.
   *
   * @returns {Promise<object>} Key information.
   */
  async generateKey({keyId, controller, operation}) {
    assert.string(keyId, 'options.keyId');
    assert.string(controller, 'options.controller');
    assert.object(operation, 'options.operation');

    const {
      invocationTarget: {
        // specific key type
        type,
        // max acceptable length of the capability chain used in a capability
        // invocation to invoke a KMS operation with the key
        maxCapabilityChainLength,
        // any public alias for the key
        publicAlias,
        // any public alias template for the key
        publicAliasTemplate
      }
    } = operation;
    assert.string(type, 'options.operation.invocationTarget.type');
    assert.optionalNumber(
      maxCapabilityChainLength,
      'options.operation.invocationTarget.maxCapabilityChainLength');
    assert.optionalString(
      publicAlias, 'options.operation.invocationTarget.publicAlias');
    assert.optionalString(
      publicAliasTemplate,
      'options.operation.invocationTarget.publicAliasTemplate');

    if(publicAlias && publicAliasTemplate) {
      throw new Error(
        'Only one of "publicAlias" or "publicAliasTemplate" may be given.');
    }

    // if `publicAliasTemplate` was given, ensure it can be parsed prior to
    // attempting key generation
    let template;
    if(publicAliasTemplate) {
      template = parseTemplate(publicAliasTemplate);
    }

    // perform key generation
    const op = getKeyOp({name: 'generateKey', type});
    const {key, keyDescription} = await op({
      keyId, type, controller,
      maxCapabilityChainLength, publicAlias, publicAliasTemplate
    });

    // add any extra key restrictions
    if(maxCapabilityChainLength !== undefined) {
      key.maxCapabilityChainLength = maxCapabilityChainLength;
    }

    // add any public alias or template
    if(publicAlias) {
      key.publicAlias = publicAlias;
      // override public key `id` with `publicAlias`
      keyDescription.id = publicAlias;
    } else if(publicAliasTemplate) {
      key.publicAliasTemplate = publicAliasTemplate;
      // compute public alias from template
      keyDescription.id = template.expand(keyDescription);
    }

    return {keyId, key, keyDescription};
  }

  /**
   * Gets the key description (no private key material) for the given key.
   *
   * @param {object} options - The options to use.
   * @param {object} options.key - The key object to use.
   * @param {string} options.controller - The key controller.
   *
   * @returns {Promise<object>} Key information.
   */
  async getKeyDescription({key, controller} = {}) {
    let type;
    if(key.type.startsWith('urn:webkms:multikey:')) {
      type = 'Multikey';
    } else {
      type = key.type;
    }
    const description = {
      '@context': key['@context'],
      id: key.id,
      type,
      controller
    };
    if(key.publicKeyMultibase) {
      description.publicKeyMultibase = key.publicKeyMultibase;
    }
    if(key.publicKeyBase58) {
      description.publicKeyBase58 = key.publicKeyBase58;
    }

    // override `id` with `publicAlias` / `publicAliasTemplate` if available
    if(key.publicAlias) {
      description.id = key.publicAlias;
    } else if(key.publicAliasTemplate) {
      // compute public alias from template
      const template = parseTemplate(key.publicAliasTemplate);
      description.id = template.expand(description);
    }

    return description;
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {object} options - The options to use.
   * @param {object} options.key - The key object to use.
   * @param {object} options.operation - The KMS operation.
   *
   * @returns {Promise<object>} An object containing `{wrappedKey}`.
   */
  async wrapKey({key, operation}) {
    assert.object(key, 'options.key');
    assert.object(operation, 'options.operation');

    const {type} = key;
    const op = getKeyOp({name: 'wrapKey', type});
    return op({kek: key, operation});
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {object} options - The options to use.
   * @param {object} options.key - The key object to use.
   * @param {object} options.operation - The KMS operation.
   *
   * @returns {Promise<object>} An object containing `{unwrappedKey}`.
   */
  async unwrapKey({key, operation}) {
    assert.object(key, 'options.key');
    assert.object(operation, 'options.operation');

    const {type} = key;
    const op = getKeyOp({name: 'unwrapKey', type});
    return op({kek: key, operation});
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {object} options.key - The key to use.
   * @param {object} options.operation - The KMS operation.
   *
   * @returns {Promise<object>} An object containing `{signatureValue}`.
   */
  async sign({key, operation}) {
    assert.object(key, 'options.key');
    assert.object(operation, 'options.operation');

    const {type} = key;
    const op = getKeyOp({name: 'sign', type});
    return op({key, operation});
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {object} options.key - The key to use.
   * @param {object} options.operation - The KMS operation.
   *
   * @returns {Promise<object>} An object containing `{verified}`.
   */
  async verify({key, operation}) {
    assert.object(key, 'options.key');
    assert.object(operation, 'options.operation');

    const {type} = key;
    const op = getKeyOp({name: 'verify', type});
    return op({key, operation});
  }

  /**
  * Derives a shared secret via the given peer public key, typically for use
  * as one parameter for computing a shared key. It should not be used as
  * a shared key itself, but rather input into a key derivation function (KDF)
  * to produce a shared key.
  *
  * @param {object} options - The options to use.
  * @param {object} options.key - The key to use.
  * @param {object} options.operation - The KMS operation.
  *
  * @returns {Promise<object>} An object containing `{secret}`.
  */
  async deriveSecret({key, operation}) {
    assert.object(key, 'options.key');
    assert.object(operation, 'options.operation');

    const {type} = key;
    const op = getKeyOp({name: 'deriveSecret', type});
    return op({key, operation});
  }
}
