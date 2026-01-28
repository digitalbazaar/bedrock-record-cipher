/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from 'node:crypto';

const AES_KW_ALGORITHM = 'id-aes256-wrap';
const AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export async function unwrapKey({secretKey, wrapped} = {}) {
  const decipher = crypto.createDecipheriv(
    AES_KW_ALGORITHM, secretKey, AES_KW_RFC3394_IV);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}

export async function wrapKey({secretKey, unwrapped} = {}) {
  const cipher = crypto.createCipheriv(
    AES_KW_ALGORITHM, secretKey, AES_KW_RFC3394_IV);
  return Buffer.concat([cipher.update(unwrapped), cipher.final()]);
}
