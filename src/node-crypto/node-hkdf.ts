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
import { byte_string } from "../basis";
import * as NodeCrypto from "node:crypto";

function makeHkdfSha(
  hashFunc: string
): (
  inputKeyingMaterial: byte_string,
  params: { salt?: byte_string; info?: byte_string; outByteLength: number }
) => Promise<byte_string> {
  return (inputKeyingMaterial, params) => {
    const { salt, info, outByteLength } = params;
    return new Promise((resolve, reject) => {
      NodeCrypto.hkdf(
        hashFunc,
        inputKeyingMaterial,
        salt ?? new Uint8Array(0),
        info ?? new Uint8Array(0),
        outByteLength,
        (err, derivedKey) => {
          if (err) {
            reject(
              new Error(`NodeCrypto.hkdf (hash_func=${hashFunc}) error: ` + err)
            );
          } else {
            resolve(new Uint8Array(derivedKey, 0, derivedKey.byteLength));
          }
        }
      );
    });
  };
}

export const hkdfSha512 = makeHkdfSha("sha512");
