/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
// FIXME: figure out `RecordCipher` integration and whether there might be
// two possible modes for record format backwards compatibility
import {decryptKeySecrets, encryptKeySecrets} from './recordEncryption.js';
import assert from 'assert-plus';

const {util: {BedrockError}} = bedrock;

export class KeyStorage {
  constructor({collectionName, recordCipher, cache} = {}) {
    this.collectionName = collectionName;
    this.recordCipher = recordCipher;
    this.cache = cache;

    this.collection = null;
    this.initialized = false;
  }

  /**
   * Inserts a new `key` object into storage. The key's `id` property must
   * be fully qualified such that it includes both the keystore ID and the
   * local ID for the key.
   *
   * @param {object} options - The options to use.
   * @param {object} options.key - The `key` object.
   *
   * @returns {Promise<object>} An object with `encryptedSecrets` instead of
   *   `secrets`.
   */
  async insert({key} = {}) {
    const {collection, recordCipher} = this;

    // remove any `controller` as it is not stored with the key; it is always
    // updated to be the current keystore controller
    key = {...key};
    delete key.controller;

    // store key record
    const now = Date.now();
    const meta = {created: now, updated: now};
    const {keystoreId, localId} = _splitKeyId({id: key.id});
    const record = {keystoreId, localId, meta, key};

    // encrypt key secrets according to configuration
    record.key = await encryptKeySecrets({recordCipher, key: record.key});

    try {
      await collection.insertOne(record);
    } catch(e) {
      if(!database.isDuplicateError(e)) {
        throw e;
      }
      throw new BedrockError('Duplicate key identifier.', {
        name: 'DuplicateError',
        details: {public: true, httpStatusCode: 409},
        cause: e
      });
    }

    return record;
  }

  /**
   * Gets the number of keys stored in a given keystore.
   *
   * @param {object} options - The options to use.
   * @param {string} options.keystoreId - The ID of the keystore.
   *
   * @returns {Promise<object>} Key count information `{count}`.
   */
  async getCount({keystoreId} = {}) {
    const count = await this.collection.countDocuments({keystoreId});
    return {count};
  }

  /**
   * Gets a previously stored key record.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {boolean} [options.useCache=true] - Whether or not to use a cached
   *   value, if available.
   *
   * @returns {Promise<object>} The key record.
   */
  async get({id, useCache = true} = {}) {
    assert.string(id, 'options.id');
    const {cache, recordCipher} = this;

    const record = (cache && useCache) ?
      await this._getCachedRecord({id}) : await this._getUncachedRecord({id});

    // decrypt key secrets according to configuration
    const key = await decryptKeySecrets({recordCipher, key: record.key});
    return {...record, key};
  }

  static async create({collectionName, recordCipher, cache} = {}) {
    const storage = new KeyStorage({collectionName, recordCipher, cache});

    bedrock.events.on('bedrock-mongodb.ready', async () => {
      await database.openCollections([storage.collectionName]);

      await database.createIndexes([{
        // cover queries by ID (<keystoreId>/<localId>)
        collection: storage.collectionName,
        fields: {keystoreId: 1, localId: 1},
        options: {unique: true}
      }]);

      storage.collection = database.collections[collectionName];
      storage.initialized = true;
    });

    return storage;
  }

  async _getCachedRecord({id}) {
    const fn = () => this._getUncachedRecord({id});
    return this.cache.memoize({key: id, fn});
  }

  async _getUncachedRecord({id}) {
    const {keystoreId, localId} = _splitKeyId({id});
    const record = await this.collection.findOne(
      {keystoreId, localId}, {projection: {_id: 0, key: 1, meta: 1}});
    if(!record) {
      throw new BedrockError('Key not found.', {
        name: 'NotFoundError',
        details: {key: id, httpStatusCode: 404, public: true}
      });
    }
    return record;
  }
}

function _splitKeyId({id}) {
  // format: <keystoreId>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    keystoreId: id.substring(0, idx),
    // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
    // where the ID is multicodec encoded 16 byte random value
    // 0x00 = identity tag, 0x10 = length (16 bytes) header
    localId: Buffer.from(base58.decode(localId.slice(1)).slice(2))
  };
}
