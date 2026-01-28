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
    type: 'X25519KeyAgreementKey2020',
    expectedContext: 'https://w3id.org/security/suites/x25519-2020/v1',
    expectedPublicKeyType: 'X25519KeyAgreementKey2020'
  },
  {type: 'urn:webkms:multikey:X25519'},
  {type: 'urn:webkms:multikey:ECDH-P-256'},
  {type: 'urn:webkms:multikey:ECDH-P-384'},
  {type: 'urn:webkms:multikey:ECDH-P-521'}
];

for(const encryptConfig of keyRecordEncryption) {
  describe(`key agreement keys ${encryptConfig.title}`, () => {
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
        expectedContext = 'https://w3id.org/security/multikey/v1',
        expectedPublicKeyType = 'Multikey',
        expectedPublicKeyProperty = 'publicKeyMultibase'
      } = supportedKey;
      describe(type, () => {
        describe('generateKey API', () => {
          it('generates a key pair', async () => {
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
              '@context', 'id', expectedPublicKeyProperty,
              'type', 'controller']);
            keyDescription['@context'].should.equal(expectedContext);
            keyDescription.id.should.equal(keyId);
            keyDescription.type.should.equal(expectedPublicKeyType);
            keyDescription.controller.should.equal(controller);
          });

          it('generates with a public alias template', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {
              id: keyId, type,
              publicAliasTemplate:
                `{+controller}#{${expectedPublicKeyProperty}}`
            };
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
              '@context', 'id', expectedPublicKeyProperty,
              'type', 'controller'
            ]);
            const expected =
              `${controller}#${keyDescription[expectedPublicKeyProperty]}`;
            keyDescription.id.should.equal(expected);
            keyDescription.type.should.equal(expectedPublicKeyType);
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

        describe('deriveSecret API', () => {
          it('derives a shared secret', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const {keyDescription: publicKey} = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            const result = await brSSM.deriveSecret(
              {keyId, operation: {invocationTarget, publicKey}});

            should.exist(result);
            result.should.be.an('object');
            result.should.have.keys(['secret']);
            const {secret} = result;
            secret.should.be.a('string');
          });

          it('fails when public types do not match', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            await brSSM.generateKey({
              keyId, controller, operation: {invocationTarget}
            });

            const publicKey = {type: 'NonMatchingType'};

            let result;
            let err;
            try {
              result = await brSSM.deriveSecret({
                keyId, operation: {publicKey}
              });
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(result);
            err.name.should.equal('Error');
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
              const plaintextBuffer = Buffer.from(
                globalThis.crypto.randomUUID(), 'utf8');
              const verifyData =
                Buffer.from(plaintextBuffer).toString('base64url');
              result = await brSSM.sign({
                keyId, operation: {invocationTarget, verifyData},
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
              '@context', 'id', expectedPublicKeyProperty,
              'type', 'controller'
            ]);
            result['@context'].should.equal(expectedContext);
            result.id.should.equal(keyId);
            result.controller.should.equal(controller);
            result.type.should.equal(expectedPublicKeyType);
          });
        });

        describe('non-key agreement key APIs', () => {
          it('throws when trying to sign', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});
            should.exist(result);

            let signResult;
            let err;
            try {
              const verifyData = Buffer
                .from(globalThis.crypto.randomUUID(), 'utf8')
                .toString('base64url');
              signResult = await brSSM.sign({keyId, operation: {verifyData}});
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(signResult);
            err.name.should.equal('Error');
          });

          it('throws when trying to wrap a key', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});
            should.exist(result);

            let signResult;
            let err;
            try {
              const unwrappedKey =
                '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';
              signResult = await brSSM.wrapKey({
                keyId, operation: {unwrappedKey}
              });
            } catch(e) {
              err = e;
            }

            should.exist(err);
            should.not.exist(signResult);
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
