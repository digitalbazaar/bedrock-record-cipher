/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {KeyStorage} from './KeyStorage.js';
import {LruCache} from '@digitalbazaar/lru-memoize';

// key record cache is stored across all storage instances where key ID
// is fully qualified to differentiate individual stores
let KEY_RECORD_CACHE;

bedrock.events.on('bedrock.init', async () => {
  const cfg = bedrock.config['ssm-mongodb'];
  let cacheConfig = cfg.keyRecordCache;

  // coerce `maxSize` w/o `sizeCalculation` to `max`
  if(cacheConfig.maxSize !== undefined &&
    cacheConfig.sizeCalculation === undefined) {
    cacheConfig = {...cacheConfig, max: cacheConfig.maxSize};
    delete cacheConfig.maxSize;
  }

  // coerce `maxAge` to `ttl` in `cacheConfig`
  if(cacheConfig.maxAge !== undefined) {
    cacheConfig = {...cacheConfig, ttl: cacheConfig.maxAge};
    delete cacheConfig.maxAge;
  }

  KEY_RECORD_CACHE = new LruCache(cacheConfig);
});

export async function createKeyStorage({collectionName, recordCipher} = {}) {
  const storage = await KeyStorage.create({
    collectionName, recordCipher, cache: KEY_RECORD_CACHE
  });

  bedrock.events.on('bedrock.start', () => {
    if(!storage.initialized) {
      throw new Error(
        '"createKeyStorage" must be called no later than the ' +
        '"bedrock.init" event.');
    }
  });

  return storage;
}
