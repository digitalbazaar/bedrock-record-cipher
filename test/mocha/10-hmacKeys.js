/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brSSM from '@bedrock/ssm-mongodb';
import {generateId} from 'bnid';

// import is for testing purposes only; not a public export
import {_createKeyRecordCipher} from '@bedrock/ssm-mongodb';

/* eslint-disable */
/*
'u' + Buffer.concat([Buffer.from([0xa2, 0x01]), Buffer.from(crypto.getRandomValues(new Uint8Array(32)))]).toString('base64url')
*/
/* eslint-enable */
const keyRecordEncryption = [
  {
    title: 'w/no wrapping',
    kek: null
  },
  {
    title: 'w/aes256 wrapping',
    kek: {
      id: 'urn:test:aes256',
      secretKeyMultibase: 'uogH3ERq9FRYOV8IuUiD2gKZs_qN6SLU-6RtbBUfzqQwGdg'
    }
  }
];
const supportedKeys = [
  {
    type: 'Sha256HmacKey2019',
    expectedContext: 'https://w3id.org/security/suites/hmac-2019/v1'
  }
];

for(const encryptConfig of keyRecordEncryption) {
  describe(`hmac keys ${encryptConfig.title}`, () => {
    const moduleConfig = bedrock.config['ssm-mongodb'];
    const oldConfigValue = moduleConfig.keyRecordEncryption;
    before(async () => {
      moduleConfig.keyRecordEncryption = {kek: encryptConfig.kek};
      await _createKeyRecordCipher();
    });
    after(() => {
      moduleConfig.keyRecordEncryption = oldConfigValue;
    });

    for(const supportedKey of supportedKeys) {
      const {
        type,
        // use multikey defaults
        expectedContext = 'https://w3id.org/security/multikey/v1'
      } = supportedKey;
      describe(type, () => {
        describe('generateKey API', () => {
          it('generates a key', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            should.exist(result);
            result.should.be.an('object');
            should.exist(result.keyId);
            result.keyId.should.equal(keyId);
            const {keyDescription} = result;
            should.exist(keyDescription);
            keyDescription.should.be.an('object');
            keyDescription.should.have.keys([
              '@context', 'id', 'type', 'controller']);
            keyDescription['@context'].should.equal(expectedContext);
            keyDescription.id.should.equal(keyId);
            keyDescription.type.should.equal(type);
            keyDescription.controller.should.equal(controller);
          });

          it('throws a DuplicateError for same key ID twice', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            let result;
            let err;
            try {
              result = await brSSM.generateKey(
                {keyId, controller, operation: {invocationTarget}});
              should.exist(result);
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(result);
            err.name.should.equal('DuplicateError');
          });
        });

        describe('sign API', () => {
          it('produces a signature', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            const operation = {
              verifyData: '2eb221b8-1777-417a-8f3a-05cdd030de12'
            };
            let err;
            let result;
            try {
              result = await brSSM.sign({keyId, operation});
            } catch(e) {
              err = e;
            }
            assertNoError(err);
            should.exist(result);
            result.should.be.an('object');
            result.should.have.property('signatureValue');
            result.signatureValue.should.be.a('string');
            result.signatureValue.should.have.length.gt(0);
          });

          it('fails when "maxCapabilityChainLength" is exceeded', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {
              id: keyId,
              type,
              maxCapabilityChainLength: 1
            };
            await brSSM.generateKey({
              keyId, controller, operation: {invocationTarget}
            });

            // mock `zcapInvocation` with `dereferencedChain` that is
            // too long (entries not checked, just length)
            const zcapInvocation = {
              dereferencedChain: [{}, {}]
            };

            let result;
            let err;
            try {
              const operation = {
                verifyData: '2eb221b8-1777-417a-8f3a-05cdd030de12'
              };
              result = await brSSM.sign({
                keyId, operation, zcapInvocation
              });
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(result);
            err.name.should.equal('Error');
            err.message.should.equal(
              'Maximum zcap invocation capability chain length (1) exceeded.');
          });

          describe('performance', () => {
            const operationCount = 10000;
            const vData = [];
            before(async () => {
              for(let i = 0; i < operationCount; ++i) {
                // uuids are 37 chars long, * 30 is ~1KiB
                let v = '';
                for(let n = 0; n < 30; ++n) {
                  v += global.crypto.randomUUID();
                }
                vData.push(v);
              }
            });
            it(`performs ${operationCount} signatures`, async function() {
              const keyId = `https://example.com/kms/${await generateId()}`;
              const controller = 'https://example.com/i/foo';
              const invocationTarget = {id: keyId, type};
              await brSSM.generateKey(
                {keyId, controller, operation: {invocationTarget}});

              this.timeout(0);
              const promises = [];
              for(let i = 0; i < operationCount; ++i) {
                const operation = {verifyData: vData[i]};
                promises.push(brSSM.sign({keyId, operation}));
              }
              let result;
              let err;
              try {
                result = await Promise.all(promises);
              } catch(e) {
                err = e;
              }
              assertNoError(err);
              should.exist(result);
              result.should.be.an('array');
              result.should.have.length(operationCount);
            });
          });
        });

        describe('verify API', () => {
          it('properly verifies data', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            const verifyData = '2eb221b8-1777-417a-8f3a-05cdd030de12';
            const operation = {
              verifyData
            };
            const result = await brSSM.sign({keyId, operation});
            const {signatureValue} = result;

            const result2 = await brSSM.verify(
              {keyId, operation: {signatureValue, verifyData}});

            result2.should.be.an('object');
            result2.should.have.property('verified');
            result2.verified.should.equal(true);
          });

          it('fails when "maxCapabilityChainLength" is exceeded', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {
              id: keyId,
              type,
              maxCapabilityChainLength: 1
            };
            await brSSM.generateKey({
              keyId, controller, operation: {invocationTarget}
            });

            const verifyData = '2eb221b8-1777-417a-8f3a-05cdd030de12';
            const operation = {
              verifyData
            };
            const {signatureValue} = await brSSM.sign({keyId, operation});

            // mock `zcapInvocation` with `dereferencedChain` that is
            // too long (entries not checked, just length)
            const zcapInvocation = {
              dereferencedChain: [{}, {}]
            };

            let result;
            let err;
            try {
              result = await brSSM.verify({
                keyId, operation: {signatureValue, verifyData},
                zcapInvocation
              });
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(result);
            err.name.should.equal('Error');
            err.message.should.equal(
              'Maximum zcap invocation capability chain length (1) exceeded.');
          });
        });

        describe('getKeyDescription API', () => {
          it('returns a key description', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            const result = await brSSM.getKeyDescription({keyId, controller});
            result.should.be.an('object');
            result.should.have.keys([
              '@context', 'id', 'type', 'controller']);
            result['@context'].should.equal(expectedContext);
            result.id.should.equal(keyId);
            result.type.should.equal(type);
            result.controller.should.equal(controller);
          });
        });

        describe('non-hmac APIs', () => {
          it('throws when trying to derive a secret', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});
            should.exist(result);

            let deriveResult;
            let err;
            try {
              deriveResult = await brSSM.deriveSecret({
                keyId, operation: {publicKey: {type}}
              });
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(deriveResult);
            err.name.should.equal('Error');
          });

          it('throws when trying to wrap a key', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});
            should.exist(result);

            let wrapResult;
            let err;
            try {
              const unwrappedKey =
                '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';
              wrapResult = await brSSM.wrapKey({
                keyId, operation: {unwrappedKey}
              });
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(wrapResult);
            err.name.should.equal('Error');
          });

          it('throws when trying to unwrap a key', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            const wrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

            let result;
            let err;
            try {
              result = await brSSM.unwrapKey({keyId, operation: {wrappedKey}});
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(result);
            err.name.should.equal('Error');
          });
        });
      });
    }
  });
}
