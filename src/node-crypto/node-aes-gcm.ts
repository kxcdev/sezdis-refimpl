/* Copyright 2023 Kotoi-Xie Consultancy, Inc. This file is a part of the

  ==== SezDis-SCIS2024 (https://kxc.dev/spl.bc/scis2024-sezdis) ====

  software project that is developed, maintained, and distributed by
  Kotoi-Xie Consultancy, Inc. (https://kxc.inc) which is also known as KXC.

  Licensed under the Apache License, Version 2.0 (the "License"); you may not
  use this file except in compliance with the License. You may obtain a copy
  of the License at http://www.apache.org/licenses/LICENSE-2.0. Unless required
  by applicable law or agreed to in writing, software distributed under the
  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
  OF ANY KIND, either express or implied. See the License for the specific
  language governing permissions and limitations under the License.
                                                                                */
import { byte_string, concatR, sliceByteString } from "../basis";
import * as NodeCrypto from "node:crypto";

function nodeCipherNameForKeyByteLength(keyByteLength: number) {
  switch (keyByteLength) {
    case 16:
      return "aes-128-gcm";
    case 24:
      return "aes-192-gcm";
    case 32:
      return "aes-256-gcm";
    default:
      throw new Error("bad key byte length for AES-GCM: " + keyByteLength);
  }
}

/// throw if any parameter is not acceptable / supported,
// return node cipher algorithm name if everything checks out
function checkAesGcmParams(params: {
  keyByteLength: number;
  tagBitLength: number;
  ivByteLength: number;
}) {
  const { keyByteLength, ivByteLength, tagBitLength } = params;
  const algorithm = nodeCipherNameForKeyByteLength(keyByteLength);

  if (![128, 120, 112, 104, 96].includes(tagBitLength)) {
    throw new Error("bad tag bit length for AES-GCM: " + tagBitLength);
  }

  if (ivByteLength * 8 !== 96) {
    throw new Error(
      "unsupported iv byte length for AES-GCM (only 96-bit iv is supported): " +
        ivByteLength
    );
  }

  return algorithm;
}

export async function aesGcmEncrypt(
  plaintext: byte_string,
  params: {
    key: byte_string;
    iv: byte_string;
    tagBitLength: number;
    associatedData?: byte_string;
  }
): Promise<byte_string> {
  const { tagBitLength, key, iv, associatedData } = params;

  const algorithm = checkAesGcmParams({
    tagBitLength,
    keyByteLength: key.byteLength,
    ivByteLength: iv.byteLength,
  });

  const cipher = NodeCrypto.createCipheriv(
    algorithm,
    NodeCrypto.createSecretKey(key),
    iv,
    { authTagLength: tagBitLength / 8 }
  );
  cipher.setAutoPadding(false);
  if (associatedData != null) cipher.setAAD(associatedData);

  const buf = cipher.update(plaintext);
  const fin = cipher.final();
  const tag = cipher.getAuthTag();

  return concatR(buf, fin, tag);
}

export async function aesGcmDecrypt(
  ciphertext: byte_string,
  params: {
    key: byte_string;
    iv: byte_string;
    tagBitLength: number;
    abortOnBadTag: boolean;
    associatedData?: byte_string;
  }
): Promise<[byte_string, boolean /* whether the auth tag is valid */]> {
  const { tagBitLength, key, iv, associatedData, abortOnBadTag } = params;

  const algorithm = checkAesGcmParams({
    tagBitLength,
    keyByteLength: key.byteLength,
    ivByteLength: iv.byteLength,
  });

  const ciphertextByteCount = ciphertext.byteLength - tagBitLength / 8;
  const data = sliceByteString(ciphertext, 0, ciphertextByteCount);
  const tag = sliceByteString(ciphertext, ciphertextByteCount);

  const decipher = NodeCrypto.createDecipheriv(
    algorithm,
    NodeCrypto.createSecretKey(key),
    iv
  );
  decipher.setAutoPadding(false);
  decipher.setAuthTag(tag);
  if (associatedData != null) decipher.setAAD(associatedData);

  const buf = decipher.update(data);

  if (abortOnBadTag) {
    decipher.final();
    return [buf, true];
  } else {
    let isTagValid: boolean;
    try {
      decipher.final();
      isTagValid = true;
    } catch (e) {
      isTagValid = false;
    }
    return [buf, isTagValid];
  }
}
