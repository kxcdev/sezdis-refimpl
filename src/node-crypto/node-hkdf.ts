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
