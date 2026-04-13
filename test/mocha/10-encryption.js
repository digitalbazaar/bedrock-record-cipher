/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {RecordCipher} from '@bedrock/record-cipher';

/* eslint-disable */
/*
'u' + Buffer.concat([Buffer.from([0xa2, 0x01]), Buffer.from(crypto.getRandomValues(new Uint8Array(32)))]).toString('base64url')
*/
/* eslint-enable */
const testParameters = [
  {
    title: 'no encryption',
    encryptConfig: {currentKekId: null},
    record: {
      secrets: {a: 1, b: 'foo', c: Buffer.from([1])},
      nonSecrets: {
        c: 2,
        d: Buffer.from([2])
      },
      moreNonSecrets: 'baz'
    },
    shouldEncrypt: false
  },
  {
    title: 'aes256 encryption w/json encoding',
    encryptConfig: {
      encoding: 'cbor',
      keks: [{
        id: 'urn:test:aes256',
        secretKeyMultibase: 'uogH3ERq9FRYOV8IuUiD2gKZs_qN6SLU-6RtbBUfzqQwGdg'
      }]
    },
    record: {
      secrets: {a: 1, b: 'foo', c: Buffer.from([1])},
      nonSecrets: {
        c: 2,
        d: Buffer.from([2])
      },
      moreNonSecrets: 'baz'
    },
    shouldEncrypt: true
  },
  {
    title: 'aes256 encryption w/cbor encoding',
    encryptConfig: {
      currentKekId: 'urn:test:aes256',
      encoding: 'json',
      keks: [{
        id: 'urn:test:aes256',
        secretKeyMultibase: 'uogH3ERq9FRYOV8IuUiD2gKZs_qN6SLU-6RtbBUfzqQwGdg'
      }]
    },
    record: {
      secrets: {a: 1, b: 'foo', c: [1]},
      nonSecrets: {
        c: 2,
        d: [2]
      },
      moreNonSecrets: 'baz'
    },
    shouldEncrypt: true
  },
  {
    title: 'aes256 encryption w/kekLoader',
    encryptConfig: {
      currentKekId: 'urn:test:aes256',
      encoding: 'json',
      async kekLoader({id}) {
        if(id === 'urn:test:aes256') {
          return {
            secretKeyMultibase:
              'uogH3ERq9FRYOV8IuUiD2gKZs_qN6SLU-6RtbBUfzqQwGdg'
          };
        }
        return null;
      }
    },
    record: {
      secrets: {a: 1, b: 'foo', c: [1]},
      nonSecrets: {
        c: 2,
        d: [2]
      },
      moreNonSecrets: 'baz'
    },
    shouldEncrypt: true
  }
];

for(const {title, encryptConfig, record, shouldEncrypt} of testParameters) {
  describe(title, () => {
    let recordCipher;
    before(async () => {
      recordCipher = await RecordCipher.create(encryptConfig);
    });

    it('encrypts record secrets', async () => {
      const encrypted = await recordCipher.encryptRecordSecrets({record});
      if(shouldEncrypt) {
        encrypted.should.not.include.key('secrets');
        encrypted.should.include.key('encryptedSecrets');
      } else {
        encrypted.should.include.key('secrets');
        encrypted.should.not.include.key('encryptedSecrets');
      }
    });

    it('decrypts record secrets', async () => {
      const encrypted = await recordCipher.encryptRecordSecrets({record});
      const decrypted = await recordCipher.decryptRecordSecrets({
        record: encrypted
      });
      decrypted.should.include.key('secrets');
      decrypted.should.not.include.key('encryptedSecrets');
      decrypted.should.deep.equal(record);
    });

    if(encryptConfig.kekLoader) {
      it('ensures lazy-load is only called once', async () => {
        let calls = 0;
        const modifiedConfig = {...encryptConfig};
        const {kekLoader} = modifiedConfig;
        modifiedConfig.kekLoader = (...args) => {
          calls++;
          return kekLoader(...args);
        };
        recordCipher = await RecordCipher.create(modifiedConfig);
        for(let i = 0; i < 3; ++i) {
          await recordCipher.encryptRecordSecrets({record});
        }
        calls.should.equal(1);
      });
    }
  });
}
