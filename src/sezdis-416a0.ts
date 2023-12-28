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
  byte_string,
  concatR,
  encodeByteStringAsHex,
  sliceByteString,
} from "./basis";
import {
  makeConcreteSezDisScheme,
  makeConcreteSezDisSchemeInstance,
  SchemeParameter,
  SealingInternalResult,
  SezDisConcreteScheme,
  SezDisConcreteSchemeInstance,
} from "./sezdis-generic";

/// The primitives needed for the concrete construction SezDis416a0
//
// SezDis416a0's choice of crypto primitives:
// - MAC : AES-CMAC
// - KDF : HKDF-SHA512
// - KEX : X25519
// - AEAD : AES-GCM
//
// SezDis416a0's choice of structural byte concatenation:
// - to concatenate D1..Dn,
// - first encode their lengths in decimal representation in utf8,
//   for example if length(D1) = 13, the result is 0x3133;
//   this gives us L1..Ln
// - L1..Ln is concatenated then suffixed with 0x3b (utf8 encoding for ";")
//   each separated by byte 0x2C (utf8 encoding for ","),
//   for example if L1..Ln = [13,4], this gives us "13,4;".utf8;
//   this gives us the HEADER
// - the final output is then HEADER || D1 || .. || Dn
//k
// SezDis416a0's choice of parameters:
// - AES key size: 128-bit (for both MAC and AEAD)
// - AES-GCM tag size: 128-bit
// - |A.secret| and |D.secret| : 2048-bit, wherein
//   - A refers to the Authority, and
//   - D refers to the Sealing Delegate
// - D.id : MAC(D.pub, key = KDF(A.secret, info = "D.id"), outputByteLength = 32 / 8)
// - |D.tok| : 128-bit
// - H : 128-bit
// - KEYGEN : 256-bit of KDF output
// - S : 224-bit in total, 96 MSbits as IV, rest as AES key
// - Seal Representation : C || Eph.pub

export type SezDis416a0Instance = SezDisConcreteSchemeInstance<
  byte_string /* 256-bit, PublicKey type for X25519 */,
  byte_string /* 256-bit, PrivateKey type for X25519 */,
  byte_string /* 416-bit, Seal Representation, simply concatenation of ephPublicKey and sealCiphertext */
>;

export type SezDis416a0SchemeParameter = SchemeParameter<
  byte_string /* PublicKey type for X25519 */,
  byte_string /* PrivateKey type for X25519 */,
  byte_string /* Seal Representation, simply concatenation of ephPublicKey and sealCiphertext */,
  SezDis416aDatabaseIntf /* Instance Identity, the database itself */
>;

export type SezDis416a0ConcreteScheme = SezDisConcreteScheme<
  byte_string /* PublicKey type for X25519 */,
  byte_string /* PrivateKey type for X25519 */,
  byte_string /* Seal Representation, simply concatenation of ephPublicKey and sealCiphertext */,
  SezDis416aDatabaseIntf /* Instance Identity, the database itself */
>;

export type SezDis416a0RequiredPrimitives = {
  aesGcmEncrypt(
    plaintext: byte_string,
    params: {
      key: byte_string;
      iv: byte_string;
      tagBitLength: number;
      associatedData?: byte_string;
    }
  ): Promise<byte_string>;

  aesGcmDecrypt(
    ciphertext: byte_string,
    params: {
      key: byte_string;
      iv: byte_string;
      tagBitLength: number;
      abortOnBadTag: boolean;
      associatedData?: byte_string;
    }
  ): Promise<[byte_string, boolean /* whether the auth tag is valid */]>;

  x25519ComputeSharedSecret(
    privateKey: byte_string,
    peerPublicKey: byte_string
  ): Promise<byte_string>;

  x25519PublicFromPrivate(privateKey: byte_string): Promise<byte_string>;

  hkdfSha512(
    inputKeyingMaterial: byte_string,
    params: {
      salt?: byte_string;
      info?: byte_string;
      outByteLength: number;
    }
  ): Promise<byte_string>;

  aesCmac(
    data: byte_string,
    params: {
      key: byte_string;
      outputByteLength: number;
    }
  ): Promise<byte_string>;
};

export type SezDis416aDatabaseIntf = {
  storeDelegateInfo: (params: {
    delegateId: byte_string;
    delegatePublicKey: byte_string;
  }) => Promise<void>;
  lookupDelegateInfo: (delegateId: byte_string) => Promise<
    | {
        kind: "found";
        delegatePublicKey: byte_string;
      }
    | {
        kind: "not-found";
      }
  >;
  checkDelegatePrivilege?: (params: {
    delegateId: byte_string;
    payload: byte_string;
  }) => Promise<
    | {
        kind: "sealing-allowed-for-delegate";
      }
    | {
        kind: "insufficient-delegate-privilege";
        detailedReason?: unknown;
      }
  >;
};

export function instantiateSezDis416a0ConcreteScheme(
  scheme: SezDis416a0ConcreteScheme
): SezDis416a0Instance;
export function instantiateSezDis416a0ConcreteScheme(
  scheme: SezDis416a0ConcreteScheme,
  opts?: {
    storage?: Record<
      string /* delegateId in small-cap hex encoding */,
      { delegateId: byte_string; delegatePublicKey: byte_string }
    >;
    checkDelegatePrivilege?: SezDis416aDatabaseIntf["checkDelegatePrivilege"];
  }
): SezDis416a0Instance;
export function instantiateSezDis416a0ConcreteScheme(
  scheme: SezDis416a0ConcreteScheme,
  opts?: {
    db: SezDis416aDatabaseIntf;
  }
): SezDis416a0Instance;

export function instantiateSezDis416a0ConcreteScheme(
  scheme: SezDis416a0ConcreteScheme,
  opts?: {
    db?: SezDis416aDatabaseIntf;
    storage?: Record<
      string /* delegateId in small-cap hex encoding */,
      { delegateId: byte_string; delegatePublicKey: byte_string }
    >;
    checkDelegatePrivilege?: SezDis416aDatabaseIntf["checkDelegatePrivilege"];
  }
): SezDis416a0Instance {
  let db: SezDis416aDatabaseIntf = opts?.db as SezDis416aDatabaseIntf;
  if (db == null) {
    db = createInMemorySezDis416aDatabase({
      storage: opts?.storage,
      checkDelegatePrivilege: opts?.checkDelegatePrivilege,
    });
  }
  return makeConcreteSezDisSchemeInstance(scheme, db);
}

export function createInMemorySezDis416aDatabase(opts?: {
  storage?: Record<
    string /* delegateId in small-cap hex encoding */,
    { delegateId: byte_string; delegatePublicKey: byte_string }
  >;
  checkDelegatePrivilege?: SezDis416aDatabaseIntf["checkDelegatePrivilege"];
}): SezDis416aDatabaseIntf {
  const storage = opts?.storage ?? {};
  const hex = encodeByteStringAsHex;

  const storeDelegateInfo: SezDis416aDatabaseIntf["storeDelegateInfo"] =
    async (params: {
      delegateId: byte_string;
      delegatePublicKey: byte_string;
    }) => {
      storage[hex(params.delegateId)] = params;
    };

  const lookupDelegateInfo: SezDis416aDatabaseIntf["lookupDelegateInfo"] =
    async (delegateId: byte_string) => {
      const record = storage[hex(delegateId)];
      if (record != null) {
        return { kind: "found", delegatePublicKey: record.delegatePublicKey };
      } else {
        return { kind: "not-found" };
      }
    };

  return {
    storeDelegateInfo,
    lookupDelegateInfo,
    checkDelegatePrivilege: opts?.checkDelegatePrivilege,
  };
}

export function makeSezDis416a0ConcreteScheme(
  cryptoPrimitives: SezDis416a0RequiredPrimitives,
  opts: {
    supportingCheckDelegatePrivilege: boolean;
  }
): SezDis416a0ConcreteScheme {
  return makeConcreteSezDisScheme(
    makeSezDis416a0SchemeParameters(cryptoPrimitives, opts)
  );
}

export function makeSezDis416a0SchemeParameters(
  cryptoPrimitives: SezDis416a0RequiredPrimitives,
  opts: {
    supportingCheckDelegatePrivilege: boolean;
  }
): SezDis416a0SchemeParameter {
  const storeDelegateInfo: SezDis416a0SchemeParameter["storeDelegateInfo"] = (
    params
  ) =>
    params.schemeInstanceIdentity.storeDelegateInfo({
      delegateId: params.delegateId,
      delegatePublicKey: params.delegatePublicKey,
    });
  const lookupDelegateInfo: SezDis416a0SchemeParameter["lookupDelegateInfo"] = (
    delegateId,
    params
  ) => params.schemeInstanceIdentity.lookupDelegateInfo(delegateId);
  const checkDelegatePrivilege: SezDis416a0SchemeParameter["checkDelegatePrivilege"] =
    !opts.supportingCheckDelegatePrivilege
      ? undefined
      : (params) => {
          const f = params.schemeInstanceIdentity.checkDelegatePrivilege;
          if (!f) {
            throw new Error(
              "checkDelegatePrivilege is not supported on the particular scheme instance"
            );
          } else {
            return f(params);
          }
        };

  const primKEX: SezDis416a0SchemeParameter["primKEX"] =
    cryptoPrimitives.x25519ComputeSharedSecret;

  const primKDF: SezDis416a0SchemeParameter["primKDF"] = (ikm, params) =>
    cryptoPrimitives.hkdfSha512(ikm, params);

  const primMAC: SezDis416a0SchemeParameter["primMAC"] = (data, params) =>
    cryptoPrimitives.aesCmac(data, params);

  const primKEYGEN: SezDis416a0SchemeParameter["primKEYGEN"] = async (
    strongKeyMaterial
  ) => {
    if (strongKeyMaterial.length !== 256 / 8) {
      throw new Error(
        "SezDis416a0SchemeParameter.primKEYGEN - input size must be exactly 256-bit (as per X25519 private key)"
      );
    }
    const privateKey = strongKeyMaterial;
    const publicKey =
      await cryptoPrimitives.x25519PublicFromPrivate(privateKey);
    return { privateKey, publicKey };
  };

  const aesGcmKeyByteLength = 128 / 8;
  const aesGcmIVByteLength = 96 / 8;
  const aesGcmTagBitLength = 128;

  const primAEADEncrypt: SezDis416a0SchemeParameter["primAEADEncrypt"] = (
    plaintext,
    params
  ) => {
    const { associatedData, keyinfo } = params;
    const iv = sliceByteString(keyinfo, 0, aesGcmIVByteLength);
    const key = sliceByteString(
      keyinfo,
      aesGcmIVByteLength,
      aesGcmIVByteLength + aesGcmKeyByteLength
    );
    return cryptoPrimitives.aesGcmEncrypt(plaintext, {
      key,
      iv,
      tagBitLength: aesGcmTagBitLength,
      associatedData,
    });
  };

  const primAEADDecrypt: SezDis416a0SchemeParameter["primAEADDecrypt"] = async (
    ciphertext,
    params
  ) => {
    const { keyinfo, associatedData, abortOnBadTag } = params;
    const iv = sliceByteString(keyinfo, 0, aesGcmIVByteLength);
    const key = sliceByteString(
      keyinfo,
      aesGcmIVByteLength,
      aesGcmIVByteLength + aesGcmKeyByteLength
    );
    const [plaintext, isTagValid] = await cryptoPrimitives.aesGcmDecrypt(
      ciphertext,
      {
        key,
        iv,
        tagBitLength: aesGcmTagBitLength,
        abortOnBadTag,
        associatedData,
      }
    );
    return { plaintext, isTagValid };
  };

  const decideDelegateId: SezDis416a0SchemeParameter["decideDelegateId"] =
    async (params) => {
      const { delegatePublicKey, authoritySecret } = params;
      return await primMAC(delegatePublicKey, {
        outputByteLength: 32 / 8,
        key: await primKDF(authoritySecret, {
          info: utf8Encoder.encode("D.id"),
          outByteLength: 128 / 8,
        }),
      });
    };

  return {
    primKEX,
    primKDF,
    primMAC,
    primKEYGEN,
    primAEADEncrypt,
    primAEADDecrypt,

    structuralByteConcat: structuralByteConcatSezDis416a0,
    sealRepresentationCodec: sealRepresentationCodecSezDis416a0,

    decideDelegateId,
    storeDelegateInfo,
    lookupDelegateInfo,
    checkDelegatePrivilege,

    paramDelegateTokenByteLength: 128 / 8,
    paramHByteLength: 128 / 8,
    paramEphemeralSecretKeyMaterialByteLength: 256 / 8,
    paramAEADKeyInfoByteLength: (96 + 128) / 8,
  };
}

const utf8Encoder = new TextEncoder();

export const sealRepresentationCodecSezDis416a0: {
  encode: (
    info: SealingInternalResult<byte_string /* PublicKey */>
  ) => byte_string;
  decode: (
    repr: byte_string
  ) => SealingInternalResult<byte_string /* PublicKey */>;
} = {
  encode(info) {
    return concatR(info.ephPublicKey, info.sealCiphertext);
  },
  decode(repr: byte_string) {
    if (
      repr.length * 8 !==
      256 + // X25519 public key size
        32 + // delegateId size
        128 // AEAD tag size
    ) {
      throw new Error(
        "sealRepresentationCodecSezDis416a0.decode bad repr format"
      );
    }

    const ephPublicKey = sliceByteString(repr, 0, 256 / 8);
    const sealCiphertext = sliceByteString(repr, 256 / 8, repr.length);

    return { ephPublicKey, sealCiphertext };
  },
};

export function structuralByteConcatSezDis416a0(
  ...components: byte_string[]
): byte_string {
  const headerTextual =
    components.map((comp) => String(comp.length)).join(",") + ";";
  const header = utf8Encoder.encode(headerTextual);
  return concatR(header, ...components);
}
