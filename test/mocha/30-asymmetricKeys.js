/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as brSSM from '@bedrock/ssm-mongodb';
import * as cborg from 'cborg';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
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
    type: 'Ed25519VerificationKey2018',
    expectedContext: 'https://w3id.org/security/suites/ed25519-2018/v1',
    expectedPublicKeyType: 'Ed25519VerificationKey2018',
    expectedPublicKeyProperty: 'publicKeyBase58'
  },
  {
    type: 'Ed25519VerificationKey2020',
    expectedContext: 'https://w3id.org/security/suites/ed25519-2020/v1',
    expectedPublicKeyType: 'Ed25519VerificationKey2020'
  },
  {type: 'urn:webkms:multikey:Ed25519'},
  {type: 'urn:webkms:multikey:P-256'},
  {type: 'urn:webkms:multikey:P-384'},
  {type: 'urn:webkms:multikey:P-521'},
  {type: 'urn:webkms:multikey:BBS-BLS12-381-SHA-256'},
  {type: 'urn:webkms:multikey:BBS-BLS12-381-SHAKE-256'},
  {type: 'urn:webkms:multikey:Bls12381G2'}
];

for(const encryptConfig of keyRecordEncryption) {
  describe(`asymmetric keys ${encryptConfig.title}`, () => {
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

        describe('sign API', () => {
          it('produces a verifiable signature', async () => {
            const keyId = `https://example.com/kms/${await generateId()}`;
            const controller = 'https://example.com/i/foo';
            const invocationTarget = {id: keyId, type};
            const {keyDescription: publicKey} = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});

            const plaintextBuffer = Buffer.from(
              globalThis.crypto.randomUUID(), 'utf8');
            let verifyData;
            if(type.startsWith('urn:webkms:multikey:BBS-') ||
              type === 'urn:webkms:multikey:Bls12381G2') {
              const header = new Uint8Array();
              const messages = [plaintextBuffer];
              verifyData = Buffer.from(cborg.encode([header, messages]))
                .toString('base64url');
            } else {
              verifyData = Buffer.from(plaintextBuffer).toString('base64url');
            }
            const result = await brSSM.sign(
              {keyId, operation: {verifyData}});

            should.exist(result);
            result.should.be.an('object');
            result.should.have.keys(['signatureValue']);
            const {signatureValue} = result;
            signatureValue.should.be.a('string');

            let verifier;
            if(type.includes('Ed25519')) {
              const keyPair = await Ed25519Multikey.from(publicKey);
              verifier = keyPair.verifier();
            } else if(type.startsWith('urn:webkms:multikey:P-')) {
              const keyPair = await EcdsaMultikey.from(publicKey);
              verifier = keyPair.verifier();
            } else if(type.startsWith('urn:webkms:multikey:BBS-') ||
              type === 'urn:webkms:multikey:Bls12381G2') {
              const keyPair = await Bls12381Multikey.from(publicKey);
              verifier = keyPair.verifier();

              // do multiverify
              const presentationHeader = new Uint8Array();
              const header = new Uint8Array();
              const messages = [plaintextBuffer];
              const proof = await keyPair.deriveProof({
                signature: Buffer.from(signatureValue, 'base64url'),
                header, messages, presentationHeader,
                disclosedMessageIndexes: [0]
              });
              const verified = await verifier.multiverify({
                proof, header, presentationHeader, messages
              });
              verified.should.be.a('boolean');
              verified.should.be.true;
              return;
            }

            const {verify} = verifier;
            const verified = await verify({
              data: plaintextBuffer,
              signature: Buffer.from(signatureValue, 'base64url')
            });

            verified.should.be.a('boolean');
            verified.should.be.true;
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
              const verifyData = Buffer
                .from(globalThis.crypto.randomUUID(), 'utf8')
                .toString('base64url');
              result = await brSSM.sign({
                keyId, operation: {verifyData},
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

        describe('non-asymmetric key APIs', () => {
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
