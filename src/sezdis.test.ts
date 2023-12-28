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
/* eslint-disable @typescript-eslint/ban-ts-comment */
import {
  instantiateSezDis416a0ConcreteScheme,
  makeSezDis416a0ConcreteScheme,
  structuralByteConcatSezDis416a0,
} from "./sezdis-416a0";
import { NodeSezDis416a0RequiredPrimitives } from "./node-crypto/node-sezdes416a0-prims";
import { x25519PublicFromPrivate } from "./node-crypto/node-x25519";
import {
  byte_string,
  concatR,
  encodeByteStringAsHex,
  sliceByteString,
} from "./basis";

const utf8Encoder = new TextEncoder();
const hex = encodeByteStringAsHex;
function fromHex(data: string) {
  return Buffer.from(data, "hex");
}

function createMockByteString(byteLength: number, filler: number) {
  return new Uint8Array(Array(byteLength).fill(filler));
}

describe("SezDis416a0", () => {
  const scheme = makeSezDis416a0ConcreteScheme(
    NodeSezDis416a0RequiredPrimitives,
    {
      supportingCheckDelegatePrivilege: false,
    }
  );
  const sezdis = instantiateSezDis416a0ConcreteScheme(scheme);

  const authorityPrivateKey = createMockByteString(256 / 8, 0);
  const authorityPublicKey = fromHex(
    "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
  );
  const authoritySecrets = {
    authorityPublicKey,
    authorityPrivateKey,
    authoritySecret: createMockByteString(2048 / 8, 1),
  };

  const delegate1Secrets = {
    delegatePrivateKey: createMockByteString(256 / 8, 2),
    delegatePublicKey: fromHex(
      "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"
    ),
    delegateSecret: createMockByteString(2048 / 8, 3),
  };
  const delegate1Knowledge = {
    delegateId: fromHex("af1fe18f"),
    delegateToken: fromHex("7f1bd232f9f48ad5cb0e5f2aabbb6211"),
    authorityPublicKey,
  };

  const delegate2Secrets = {
    delegatePrivateKey: createMockByteString(256 / 8, 4),
    delegatePublicKey: fromHex(
      "ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"
    ),
    delegateSecret: createMockByteString(2048 / 8, 5),
  };
  const delegate2Knowledge = {
    delegateId: fromHex("01ea09fd"),
    delegateToken: fromHex("58f616b61499f80b047b0365e8557469"),
    authorityPublicKey,
  };

  const testVectors = [
    {
      vectorName: "empty-payload",
      payload: new Uint8Array([]),
      delegate1Seal: fromHex(
        "613c7181c204be1af8aca7ce462457bd5783e2213e5c8bbd167b69c19d12f6655c7600efeb8fa0a9f027b0f31f502cfde8c3bc91"
      ),
      delegate2Seal: fromHex(
        "d28bb7aa7961f30f85c73a2f96cb12de8cb5d9dd76417b57b188eb5ed8e1a71e8338131cd1cab271339e1788629792a23ed73c51"
      ),
    },
    {
      vectorName: "short-payload",
      payload: utf8Encoder.encode("hello"),
      delegate1Seal: fromHex(
        "6eeddef27df3b7b67c1e04df8ba6b17bbde43e39d497634832d554afef06a754d936380645413ac0cf306fed27058814077040e4"
      ),
      delegate2Seal: fromHex(
        "0c3063cccce203a1542e0fc4c2709856c3aa0d2061620e8006d0c1742ae6d82bd33d96bb656baa33b272122e83836fca5fa4c03f"
      ),
    },
    {
      vectorName: "long-payload",
      payload: new Uint8Array(Array(2048 / 8).fill(33)),
      delegate1Seal: fromHex(
        "f218d5138c2549ee662643f92ae781530f62cba2cc73a93501fd9538c7ddfa0645d80ab2299fb22cb6aa5e47b54946c132a96dcf"
      ),
      delegate2Seal: fromHex(
        "d48cad102e5918a47827b79bed4eeeb386630f410ad4ae1ce63dd4d9ede37562e8919d3d2838214ba278d902407008bdab712c99"
      ),
    },
  ];

  test("direct impl", async () => {
    // NB: we only check for delegate1
    const prims = NodeSezDis416a0RequiredPrimitives;
    const concatS = structuralByteConcatSezDis416a0;

    const delegate = { ...delegate1Secrets, ...delegate1Knowledge };
    const authoritySecret = authoritySecrets.authoritySecret;
    const testVector = testVectors[1];
    const testVectorPayload = testVector.payload;
    const testVectorSeal = testVector.delegate1Seal;

    // --- registration ceremony
    const Did = await prims.aesCmac(delegate.delegatePublicKey, {
      key: await prims.hkdfSha512(authoritySecret, {
        info: utf8Encoder.encode("D.id"),
        outByteLength: 128 / 8,
      }),
      outputByteLength: 32 / 8,
    });
    expect(hex(Did)).toBe(hex(delegate1Knowledge.delegateId));

    const K = await prims.x25519ComputeSharedSecret(
      authorityPrivateKey,
      delegate.delegatePublicKey
    );
    const Dtok = await prims.hkdfSha512(concatS(K, Did, authoritySecret), {
      outByteLength: 128 / 8,
    });
    expect(hex(Dtok)).toBe(hex(delegate1Knowledge.delegateToken));

    // --- sealing operation
    const H = await prims.aesCmac(testVectorPayload, {
      key: Dtok,
      outputByteLength: 128 / 8,
    });
    const ephPrivate = await prims.hkdfSha512(
      concatS(H, delegate.delegateSecret),
      {
        outByteLength: 256 / 8,
      }
    );
    const ephPublic = await prims.x25519PublicFromPrivate(ephPrivate);
    const S = await prims.hkdfSha512(
      await prims.x25519ComputeSharedSecret(ephPrivate, authorityPublicKey),
      {
        outByteLength: 224 / 8,
      }
    );
    const C = await prims.aesGcmEncrypt(Did, {
      iv: sliceByteString(S, 0, 96 / 8),
      key: sliceByteString(S, 96 / 8),
      associatedData: H,
      tagBitLength: 128,
    });
    const seal = concatR(ephPublic, C);
    expect(hex(seal)).toBe(hex(testVectorSeal));

    // --- verification operation
    const S_ = await prims.hkdfSha512(
      await prims.x25519ComputeSharedSecret(authorityPrivateKey, ephPublic),
      {
        outByteLength: 224 / 8,
      }
    );
    expect(hex(S_)).toBe(hex(S));

    const [Did_] = await prims.aesGcmDecrypt(C, {
      iv: sliceByteString(S_, 0, 96 / 8),
      key: sliceByteString(S_, 96 / 8),
      tagBitLength: 128,
      abortOnBadTag: false,
    });
    expect(hex(Did_)).toBe(hex(Did));

    const Dtok_ = await prims.hkdfSha512(
      concatS(
        await prims.x25519ComputeSharedSecret(
          authorityPrivateKey,
          delegate.delegatePublicKey
        ),
        Did_,
        authoritySecret
      ),
      {
        outByteLength: 128 / 8,
      }
    );
    expect(hex(Dtok_)).toBe(hex(Dtok));

    const H_ = await prims.aesCmac(testVectorPayload, {
      key: Dtok_,
      outputByteLength: 128 / 8,
    });
    expect(hex(H_)).toBe(hex(H));

    const [, valid] = await prims.aesGcmDecrypt(C, {
      iv: sliceByteString(S_, 0, 96 / 8),
      key: sliceByteString(S_, 96 / 8),
      tagBitLength: 128,
      associatedData: H_,
      abortOnBadTag: false,
    });
    expect(valid).toBe(true);
  });

  describe("sezdis-416a0 impl tests", () => {
    test("test scalars sanity", async () => {
      [delegate1Knowledge, delegate2Knowledge].forEach(
        ({ delegateId, delegateToken }) => {
          expect(delegateId.length).toBe(32 / 8);
          expect(delegateToken.length).toBe(128 / 8);
        }
      );

      testVectors
        .flatMap(({ delegate1Seal, delegate2Seal }) => [
          delegate1Seal,
          delegate2Seal,
        ])
        .forEach((seal) => {
          expect(seal.length).toBe(416 / 8);
        });

      const ofAuthority = (s: typeof authoritySecrets) => ({
        publicKey: s.authorityPublicKey,
        privateKey: s.authorityPrivateKey,
      });
      const ofDelegate = (s: typeof delegate1Secrets) => ({
        publicKey: s.delegatePublicKey,
        privateKey: s.delegatePrivateKey,
      });
      await Promise.all(
        [
          ofAuthority(authoritySecrets),
          ofDelegate(delegate1Secrets),
          ofDelegate(delegate2Secrets),
        ].map(async ({ publicKey, privateKey }) => {
          expect(hex(publicKey)).toBe(
            hex(await x25519PublicFromPrivate(privateKey))
          );
        })
      );
    });

    test("register", async () => {
      const d1 = await sezdis.registration(delegate1Secrets, authoritySecrets);

      expect(hex(d1.delegateId)).toBe(hex(delegate1Knowledge.delegateId));
      expect(hex(d1.delegateToken)).toBe(hex(delegate1Knowledge.delegateToken));

      const d2 = await sezdis.registration(delegate2Secrets, authoritySecrets);

      expect(hex(d2.delegateId)).toBe(hex(delegate2Knowledge.delegateId));
      expect(hex(d2.delegateToken)).toBe(hex(delegate2Knowledge.delegateToken));
    });

    describe("sealing", () => {
      testVectors.forEach(
        ({ vectorName, payload, delegate1Seal, delegate2Seal }) => {
          // @ts-ignore
          const go = (label, delegateKnowledge, delegateSecrets, seal) => {
            test(`vector ${vectorName} ${label} sealing`, async () => {
              expect(
                hex(
                  await sezdis.sealing(
                    payload,
                    delegateKnowledge,
                    delegateSecrets
                  )
                )
              ).toBe(hex(seal));
            });
          };
          go("delegate1", delegate1Knowledge, delegate1Secrets, delegate1Seal);
          go("delegate2", delegate2Knowledge, delegate2Secrets, delegate2Seal);
        }
      );
    });

    describe("verification", () => {
      testVectors.forEach(
        ({ vectorName, payload, delegate1Seal, delegate2Seal }) => {
          async function registerDelegates() {
            await sezdis.registration(delegate1Secrets, authoritySecrets);
            await sezdis.registration(delegate2Secrets, authoritySecrets);
          }

          const go = (
            label: string,
            delegateKnowledge: typeof delegate1Knowledge,
            delegateSecrets: typeof delegate1Secrets,
            goodSeal: byte_string,
            badSeal: byte_string
          ) => {
            test(`vector ${vectorName} ${label} verification: good seal`, async () => {
              await registerDelegates();

              const result = await sezdis.verification(
                payload,
                { seal: goodSeal, shouldCheckDelegatePrivilege: false },
                authoritySecrets
              );

              if (result.kind === "aborted") {
                console.error("verification aborted on good seal: ", result);
              }
              expect(result.kind).toBe("valid-seal");
              if (result.kind !== "valid-seal") throw new Error("panic"); // make typescript happy
              expect(hex(result.delegateId)).toBe(
                hex(delegateKnowledge.delegateId)
              );
              expect(hex(result.delegatePublicKey)).toBe(
                hex(delegateSecrets.delegatePublicKey)
              );
            });
            test(`vector ${vectorName} ${label} verification: bad seal`, async () => {
              await registerDelegates();

              const result = await sezdis.verification(
                payload,
                { seal: badSeal, shouldCheckDelegatePrivilege: false },
                authoritySecrets
              );

              if (result.kind === "valid-seal") {
                console.error("verification succeeded on bad seal: ", result);
              }
              expect(result.kind).toBe("aborted");
              if (result.kind !== "aborted") throw new Error("panic"); // make typescript happy
              expect(result.sensitiveAdditionalInformation.reasonKind).toBe(
                "invalid-verification-tag"
              );
              if (
                result.sensitiveAdditionalInformation.reasonKind !==
                "invalid-verification-tag"
              )
                throw new Error("panic"); // make typescript happy
              expect(
                hex(result.sensitiveAdditionalInformation.candidateDelegateId)
              ).toBe(hex(delegateKnowledge.delegateId));
            });
          };

          const delegate1SealBad = sliceByteString(delegate1Seal);
          delegate1SealBad[(256 + 32) / 8] ^= 0x1a;

          const delegate2SealBad = sliceByteString(delegate2Seal);
          delegate2SealBad[(256 + 32) / 8] ^= 0x1a;

          go(
            "delegate1",
            delegate1Knowledge,
            delegate1Secrets,
            delegate1Seal,
            delegate1SealBad
          );
          go(
            "delegate2",
            delegate2Knowledge,
            delegate2Secrets,
            delegate2Seal,
            delegate2SealBad
          );
        }
      );
    });
  });
});
