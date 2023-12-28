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
import {
  x25519ComputeSharedSecret,
  x25519PublicFromPrivate,
} from "./node-x25519";
import { encodeByteStringAsHex } from "../basis";

const hex = encodeByteStringAsHex;
function fromHex(data: string) {
  return Buffer.from(data, "hex");
}

describe("node-x25519 (hacl-wasm)", () => {
  // source: https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
  const testVectors = [
    {
      testVectorName: "rfc7748sec6.1",
      aPrivateKey:
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      aPublicKey:
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      bPrivateKey:
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
      bPublicKey:
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      sharedSecret:
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    },
  ];

  function makePair(privateKey: string, publicKey: string, pairName?: string) {
    return {
      pairName,
      privateKey: fromHex(privateKey),
      publicKey: fromHex(publicKey),
    };
  }

  testVectors.forEach(
    ({
      testVectorName,
      aPrivateKey,
      aPublicKey,
      bPrivateKey,
      bPublicKey,
      sharedSecret,
    }) => {
      const pairs = [
        makePair(aPrivateKey, aPublicKey, "alice"),
        makePair(bPrivateKey, bPublicKey, "bob"),
      ];
      pairs.forEach(({ publicKey, privateKey, pairName }) => {
        test(`x25519PublicFromPrivate (${pairName} of ${testVectorName})`, async () => {
          expect(hex(await x25519PublicFromPrivate(privateKey))).toBe(
            hex(publicKey)
          );
        });
      });
      test(`x25519ComputeSharedSecret (${testVectorName} a:b)`, async () => {
        expect(
          hex(
            await x25519ComputeSharedSecret(
              fromHex(aPrivateKey),
              fromHex(bPublicKey)
            )
          )
        ).toBe(sharedSecret);
      });
      test(`x25519ComputeSharedSecret (${testVectorName} b:a)`, async () => {
        expect(
          hex(
            await x25519ComputeSharedSecret(
              fromHex(bPrivateKey),
              fromHex(aPublicKey)
            )
          )
        ).toBe(sharedSecret);
      });
    }
  );
});
