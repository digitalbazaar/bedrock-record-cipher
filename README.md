# bedrock-ssm-mongodb

## Usage
This API is designed to be accessed using the
[bedrock-package-manager](https://github.com/digitalbazaar/bedrock-package-manager#usage)
API.

```js
import * as brPackageManager from '@bedrock/package-manager';

// require this module in the application
// it registers itself with bedrock-package-manager
import '@bedrock/ssm-mongodb';

// use the API
export async function callMethod({method, options, plugin}) {
  // the alias for bedrock-ssm-mongodb is 'ssm-v1'
  // the type for bedrock-ssm-mongodb is 'webkms-module'
  const {packageName} = brPackageManager.get(
    {alias: plugin, type: 'webkms-module'});
  const store = await import(packageName);

  const result = await store[method](options);

  return result;
}
```

## API Reference
<a name="module_bedrock-ssm-mongodb"></a>

## bedrock-ssm-mongodb

* [bedrock-ssm-mongodb](#module_bedrock-ssm-mongodb)
    * [.getKeyCount(options)](#module_bedrock-ssm-mongodb.getKeyCount) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.generateKey(options)](#module_bedrock-ssm-mongodb.generateKey) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.wrapKey(options)](#module_bedrock-ssm-mongodb.wrapKey) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.unwrapKey(options)](#module_bedrock-ssm-mongodb.unwrapKey) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.sign(options)](#module_bedrock-ssm-mongodb.sign) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.verify(options)](#module_bedrock-ssm-mongodb.verify) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.deriveSecret(options)](#module_bedrock-ssm-mongodb.deriveSecret) ⇒ <code>Promise.&lt;object&gt;</code>

<a name="module_bedrock-ssm-mongodb.getKeyCount"></a>

### bedrock-ssm-mongodb.getKeyCount(options) ⇒ <code>Promise.&lt;object&gt;</code>
Gets the number of keys in a given keystore.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Key count information.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keystoreId | <code>string</code> | The ID of the keystore. |

<a name="module_bedrock-ssm-mongodb.generateKey"></a>

### bedrock-ssm-mongodb.generateKey(options) ⇒ <code>Promise.&lt;object&gt;</code>
Generates a new key.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Key information.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.controller | <code>string</code> | The key controller. |
| options.operation | <code>object</code> | The KMS operation. |

<a name="module_bedrock-ssm-mongodb.wrapKey"></a>

### bedrock-ssm-mongodb.wrapKey(options) ⇒ <code>Promise.&lt;object&gt;</code>
Wraps a cryptographic key using a key encryption key (KEK).

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - An object containing `{wrappedKey}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>object</code> | The KMS operation. |
| [options.zcapInvocation] | <code>object</code> | The zcap invocation used to   run the KMS operation; if the KMS operation was invoked via zcap. |

<a name="module_bedrock-ssm-mongodb.unwrapKey"></a>

### bedrock-ssm-mongodb.unwrapKey(options) ⇒ <code>Promise.&lt;object&gt;</code>
Unwraps a cryptographic key using a key encryption key (KEK).

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - An object containing `{unwrappedKey}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>object</code> | The KMS operation. |
| [options.zcapInvocation] | <code>object</code> | The zcap invocation used to   run the KMS operation; if the KMS operation was invoked via zcap. |

<a name="module_bedrock-ssm-mongodb.sign"></a>

### bedrock-ssm-mongodb.sign(options) ⇒ <code>Promise.&lt;object&gt;</code>
Signs some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - An object containing `{signatureValue}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>object</code> | The KMS operation. |
| [options.zcapInvocation] | <code>object</code> | The zcap invocation used to   run the KMS operation; if the KMS operation was invoked via zcap. |

<a name="module_bedrock-ssm-mongodb.verify"></a>

### bedrock-ssm-mongodb.verify(options) ⇒ <code>Promise.&lt;object&gt;</code>
Verifies some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - An object containing `{verified}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>object</code> | The KMS operation. |
| [options.zcapInvocation] | <code>object</code> | The zcap invocation used to   run the KMS operation; if the KMS operation was invoked via zcap. |

<a name="module_bedrock-ssm-mongodb.deriveSecret"></a>

### bedrock-ssm-mongodb.deriveSecret(options) ⇒ <code>Promise.&lt;object&gt;</code>
Derives a shared secret via the given peer public key, typically for use
as one parameter for computing a shared key. It should not be used as
a shared key itself, but rather input into a key derivation function (KDF)
to produce a shared key.

**Kind**: static method of [<code>bedrock-ssm-mongodb</code>](#module_bedrock-ssm-mongodb)  
**Returns**: <code>Promise.&lt;object&gt;</code> - An object containing `{secret}`.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The key ID to use. |
| options.operation | <code>object</code> | The KMS operation. |
| [options.zcapInvocation] | <code>object</code> | The zcap invocation used to   run the KMS operation; if the KMS operation was invoked via zcap. |

