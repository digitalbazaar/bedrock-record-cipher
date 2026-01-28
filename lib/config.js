/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';

const cfg = config['ssm-mongodb'] = {};
cfg.keyRecordCache = {
  max: 100,
  ttl: 5000
};

// used to encrypt key secrets that are stored in key records
cfg.keyRecordEncryption = {
  // current key encryption key for wrapping randomly-generated content
  // encryption keys used to encrypt key secrets at key record creation time;
  // existing key records w/o key secrets encryption will be unaffected by a
  // configuration change here
  kek: null,
  /*
  kek: {
    id: '<a key identifier>',
    secretKeyMultibase: '<multibase encoding of an AES-256 secret key>'
  }*/
};
