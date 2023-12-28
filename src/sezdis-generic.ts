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
import { byte_string } from "./basis";

export type SezDisConcreteSchemeInstance<
  PublicKey,
  PrivateKey,
  SealRepresentation,
> = {
  registration(
    operationParams: {
      delegatePublicKey: PublicKey;
    },
    authoritySecrets: {
      authoritySecret: byte_string;
      authorityPrivateKey: PrivateKey;
    }
  ): Promise<RegistrationResult>;
  sealing(
    payload: byte_string,
    delegateKnowledge: {
      delegateId: byte_string;
      delegateToken: byte_string;
      authorityPublicKey: PublicKey;
    },
    delegateSecrets: {
      delegatePrivateKey: PublicKey;
      delegateSecret: byte_string;
    }
  ): Promise<SealRepresentation>;
  verification(
    payload: byte_string,
    operationParams: {
      seal: SealRepresentation;
      shouldCheckDelegatePrivilege: boolean;
    },
    authoritySecrets: {
      authoritySecret: byte_string;
      authorityPrivateKey: PrivateKey;
    }
  ): Promise<VerificationResult<PublicKey>>;
};

export function makeConcreteSezDisSchemeInstance<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
>(
  scheme: SezDisConcreteScheme<
    PublicKey,
    PrivateKey,
    SealRepresentation,
    SchemeInstanceIdentity
  >,
  schemeInstanceIdentity: SchemeInstanceIdentity
): SezDisConcreteSchemeInstance<PublicKey, PrivateKey, SealRepresentation> {
  type R = SezDisConcreteSchemeInstance<
    PublicKey,
    PrivateKey,
    SealRepresentation
  >;
  const registration: R["registration"] = (operationParams, authoritySecrets) =>
    scheme.registration(operationParams, {
      ...authoritySecrets,
      schemeInstanceIdentity,
    });
  const sealing: R["sealing"] = (payload, delegateKnowledge, delegateSecrets) =>
    scheme.sealing(
      payload,
      {
        ...delegateSecrets,
        delegateId: delegateKnowledge.delegateId,
        delegateToken: delegateKnowledge.delegateToken,
      },
      {
        authorityPublicKey: delegateKnowledge.authorityPublicKey,
        schemeInstanceIdentity,
      }
    );
  const verification: R["verification"] = (
    payload,
    operationParams,
    authoritySecrets
  ) =>
    scheme.verification(payload, operationParams, {
      ...authoritySecrets,
      schemeInstanceIdentity,
    });

  return {
    registration,
    sealing,
    verification,
  };
}

export type SezDisConcreteScheme<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
> = {
  registration(
    operationParams: {
      delegatePublicKey: PublicKey;
    },
    schemeInstanceParams: {
      authoritySecret: byte_string;
      authorityPrivateKey: PrivateKey;
      schemeInstanceIdentity: SchemeInstanceIdentity;
    }
  ): Promise<RegistrationResult>;
  sealing(
    payload: byte_string,
    operationParams: {
      delegatePrivateKey: PublicKey;
      delegateId: byte_string;
      delegateToken: byte_string;
      delegateSecret: byte_string;
    },
    schemeInstanceParams: {
      authorityPublicKey: PublicKey;
      schemeInstanceIdentity: SchemeInstanceIdentity;
    }
  ): Promise<SealRepresentation>;
  verification(
    payload: byte_string,
    operationParams: {
      seal: SealRepresentation;
      shouldCheckDelegatePrivilege: boolean;
    },
    schemeInstanceParams: {
      authoritySecret: byte_string;
      authorityPrivateKey: PrivateKey;
      schemeInstanceIdentity: SchemeInstanceIdentity;
    }
  ): Promise<VerificationResult<PublicKey>>;
  readonly schemeParameters: SchemeParameter<
    PublicKey,
    PrivateKey,
    SealRepresentation,
    SchemeInstanceIdentity
  >;
};

export function makeConcreteSezDisScheme<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
>(
  schemeParams: SchemeParameter<
    PublicKey,
    PrivateKey,
    SealRepresentation,
    SchemeInstanceIdentity
  >
): SezDisConcreteScheme<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity
> {
  return Object.freeze({
    registration: (operationParams, schemeInstanceParams) =>
      registration(operationParams, schemeInstanceParams, schemeParams),
    sealing: (payload, operationParams, schemeInstanceParams) =>
      sealing(payload, operationParams, schemeInstanceParams, schemeParams),
    verification: (payload, operationParams, schemeInstanceParams) =>
      verification(
        payload,
        operationParams,
        schemeInstanceParams,
        schemeParams
      ),
    schemeParameters: schemeParams,
  });
}

export function greeting() {
  return "hello?";
}

/// key exchange crypto primitive
export type PrimitiveKEX<PublicKey, PrivateKey> = (
  privateKey: PrivateKey,
  peerPublicKey: PublicKey
) => Promise<byte_string>;

export type PrimitiveKDF = (
  inputKeyMaterial: byte_string,
  params: {
    outByteLength: number;
    salt?: byte_string;
    info?: byte_string;
  }
) => Promise<byte_string>;

export type PrimitiveMAC = (
  data: byte_string,
  params: {
    key: byte_string;
    outputByteLength: number;
  }
) => Promise<byte_string>;

export type PrimitiveKEYGEN<PublicKey, PrivateKey> = (
  /// the input key material is assumed to be strong,
  // that is, as if drawn from a uniform distribution over
  // all possible byte strings of the same length as the input
  strongKeyMaterial: byte_string
) => Promise<{
  publicKey: PublicKey;
  privateKey: PrivateKey;
}>;

export type PrimitiveAEADEncrypt = (
  plaintext: byte_string,
  params: {
    keyinfo: byte_string;
    associatedData?: byte_string;
  }
) => Promise<byte_string>;

export type PrimitiveAEADDecrypt = (
  ciphertext: byte_string,
  params: {
    keyinfo: byte_string;
    abortOnBadTag: boolean;
    associatedData?: byte_string;
  }
) => Promise<{ plaintext: byte_string; isTagValid: boolean }>;

export type SchemeParameter<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
> = {
  primKEX: PrimitiveKEX<PublicKey, PrivateKey>;
  primKDF: PrimitiveKDF;
  primMAC: PrimitiveMAC;
  primKEYGEN: PrimitiveKEYGEN<PublicKey, PrivateKey>;
  primAEADEncrypt: PrimitiveAEADEncrypt;
  primAEADDecrypt: PrimitiveAEADDecrypt;

  paramDelegateTokenByteLength: number;
  paramHByteLength: number;
  paramEphemeralSecretKeyMaterialByteLength: number;
  paramAEADKeyInfoByteLength: number;

  structuralByteConcat: (...components: byte_string[]) => byte_string;

  sealRepresentationCodec: {
    encode: (info: SealingInternalResult<PublicKey>) => SealRepresentation;
    decode: (repr: SealRepresentation) => SealingInternalResult<PublicKey>;
  };

  /// can be non-deterministic but must generate unique id for
  // each distinct delegatePublicKey within the scope of each scheme schemeInstance
  decideDelegateId: (params: {
    delegatePublicKey: PublicKey;
    authoritySecret: byte_string;
    authorityPrivateKey: PrivateKey;
    schemeInstanceIdentity: SchemeInstanceIdentity;
  }) => Promise<byte_string>;

  /// the public key must be retrievable later by a lookup with the delegateId
  // for any given schemeInstanceIdentity
  storeDelegateInfo: (params: {
    delegateId: byte_string;
    delegatePublicKey: PublicKey;
    schemeInstanceIdentity: SchemeInstanceIdentity;
  }) => Promise<void>;

  lookupDelegateInfo: (
    delegateId: byte_string,
    params: {
      schemeInstanceIdentity: SchemeInstanceIdentity;
    }
  ) => Promise<
    | {
        kind: "found";
        delegatePublicKey: PublicKey;
      }
    | {
        kind: "not-found";
      }
  >;

  /// the Authority may maintain a permission system that stipulate which payloads
  // each delegate could sign and if so, it is natural to make this check
  // as part of the Verification Operation. Although, this is completely optional.
  //
  // Side note: such checks may be stateful or stateless depending on the use case
  //            and the SezDis Sealing Scheme does not care about this.
  checkDelegatePrivilege?: (params: {
    delegateId: byte_string;
    payload: byte_string;
    schemeInstanceIdentity: SchemeInstanceIdentity;
  }) => Promise<DelegatePrivilegeCheckResult>;
};

export type DelegatePrivilegeCheckResult =
  | {
      kind: "sealing-allowed-for-delegate";
    }
  | {
      kind: "insufficient-delegate-privilege";
      detailedReason?: unknown;
    };

export type RegistrationResult = {
  delegateId: byte_string;
  delegateToken: byte_string;
};

export type SealingInternalResult<PublicKey> = {
  ephPublicKey: PublicKey;
  sealCiphertext: byte_string;
};

export type VerificationResult<PublicKey> =
  | {
      kind: "valid-seal"; // iff the input seal is genuine
      delegateId: byte_string;
      delegatePublicKey: PublicKey;
    }
  | {
      kind: "aborted"; // iff the input seal / payload is either corrupted or forged

      // if the caller is acting as a verification oracle,
      // this field shall be striped before returning to the querier of the oracle
      sensitiveAdditionalInformation:
        | {
            reasonKind: "delegate-not-found";
            candidateDelegateId: byte_string;
          }
        | {
            reasonKind: "invalid-verification-tag";
            candidateDelegateId: byte_string;
            candidateDelegatePublicKey: PublicKey;
          }
        | {
            reasonKind: "insufficient-delegate-privilege";
            detailedReason?: unknown;
            delegateId: byte_string;
            delegatePublicKey: PublicKey;
          };
    };

export async function registration<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
>(
  operationParams: {
    delegatePublicKey: PublicKey;
  },
  schemeInstanceParams: {
    authoritySecret: byte_string;
    authorityPrivateKey: PrivateKey;
    schemeInstanceIdentity: SchemeInstanceIdentity;
  },
  schemeParams: SchemeParameter<
    PublicKey,
    PrivateKey,
    SealRepresentation,
    SchemeInstanceIdentity
  >
): Promise<RegistrationResult> {
  const { authoritySecret, authorityPrivateKey, schemeInstanceIdentity } =
    schemeInstanceParams;
  const { delegatePublicKey } = operationParams;
  const {
    primKEX,
    primKDF,

    structuralByteConcat: concatS,
    decideDelegateId,

    paramDelegateTokenByteLength,

    storeDelegateInfo,
  } = schemeParams;

  // --- Step 1: decide the delegateId (D.id in paper)
  const delegateId = await decideDelegateId({
    authorityPrivateKey,
    authoritySecret,
    delegatePublicKey,
    schemeInstanceIdentity,
  });

  // --- Step 2: compute the delegateToken (D.tok in paper)
  const K = await primKEX(authorityPrivateKey, delegatePublicKey);
  const delegateToken = await primKDF(concatS(K, delegateId, authoritySecret), {
    outByteLength: paramDelegateTokenByteLength,
  });

  // --- Step 3: remember the (delegateId, delegateToken) in the Authority's database, if necessary
  await storeDelegateInfo({
    delegateId,
    delegatePublicKey,
    schemeInstanceIdentity,
  });

  // --- Step 4: pass delegateId and delegateToken to the Delegate who is registering
  return {
    delegateId,
    delegateToken,
  };
}

export async function sealing<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
>(
  payload: byte_string,
  operationParams: {
    delegatePrivateKey: PublicKey;
    delegateId: byte_string;
    delegateToken: byte_string;
    delegateSecret: byte_string;
  },
  schemeInstanceParams: {
    authorityPublicKey: PublicKey;
  },
  schemeParams: SchemeParameter<
    PublicKey,
    PrivateKey,
    SealRepresentation,
    SchemeInstanceIdentity
  >
): Promise<SealRepresentation> {
  const { delegateId, delegateToken, delegateSecret } = operationParams;
  const { authorityPublicKey } = schemeInstanceParams;
  const {
    primMAC,
    primKDF,
    primKEYGEN,
    primKEX,
    primAEADEncrypt,

    structuralByteConcat: concatS,
    sealRepresentationCodec,

    paramHByteLength,
    paramEphemeralSecretKeyMaterialByteLength,
    paramAEADKeyInfoByteLength,
  } = schemeParams;

  // --- Step 1: calculate the hash of the payload keyed with delegateToken,
  //             which is intended to only be known / computable by the
  //             Sealing Delegate and the Authority
  const H = await primMAC(payload, {
    key: delegateToken,
    outputByteLength: paramHByteLength,
  });

  // --- Step 2: calculation of the ephemeral key pair,
  //             which is completely deterministic and (practically) unique to
  //             every (payload, delegateToken, delegateSecrete) triple,
  //             and is intended to only be known / computable by the
  //             Sealing Delegate
  const { privateKey: ephPrivateKey, publicKey: ephPublicKey } =
    await primKEYGEN(
      await primKDF(concatS(H, delegateSecret), {
        outByteLength: paramEphemeralSecretKeyMaterialByteLength,
      })
    );

  // --- Step 3: calculation of the sealing AEAD key, which is
  //             a common key based on asymmetric key exchange
  //             between the Sealing Delegate (the only one who knows ephPrivateKey)
  //             and the Authority (the only one who knows authorityPrivateKey)
  const sealingKeyInfo /* S in paper */ = await primKDF(
    await primKEX(ephPrivateKey, authorityPublicKey),
    { outByteLength: paramAEADKeyInfoByteLength }
  );

  // --- Step 4: use AEAD to encrypt delegateID as well as to calculate
  //             a MAC over H (which is the hash of payload keyed with delegateToken)
  //             to form the central part of the generating seal
  const sealCiphertext /* C in paper */ = await primAEADEncrypt(delegateId, {
    keyinfo: sealingKeyInfo,
    associatedData: H,
  });

  // --- Step 5: the final generated seal therefore carry info about ephPublicKey and the AEAD ciphertext
  return sealRepresentationCodec.encode({ ephPublicKey, sealCiphertext });
}

export async function verification<
  PublicKey,
  PrivateKey,
  SealRepresentation,
  SchemeInstanceIdentity,
>(
  payload: byte_string,
  operationParams: {
    seal: SealRepresentation;
    shouldCheckDelegatePrivilege: boolean;
  },
  schemeInstanceParams: {
    authoritySecret: byte_string;
    authorityPrivateKey: PrivateKey;
    schemeInstanceIdentity: SchemeInstanceIdentity;
  },
  schemeParams: SchemeParameter<
    PublicKey,
    PrivateKey,
    SealRepresentation,
    SchemeInstanceIdentity
  >
): Promise<VerificationResult<PublicKey>> {
  const { seal, shouldCheckDelegatePrivilege } = operationParams;
  const { authorityPrivateKey, authoritySecret, schemeInstanceIdentity } =
    schemeInstanceParams;
  const {
    primMAC,
    primKDF,
    primKEX,
    primAEADDecrypt,

    structuralByteConcat: concatS,
    sealRepresentationCodec,

    lookupDelegateInfo,
    checkDelegatePrivilege,

    paramDelegateTokenByteLength,
    paramHByteLength,
  } = schemeParams;

  // --- Step 0: decode seal representation
  const { ephPublicKey, sealCiphertext } = sealRepresentationCodec.decode(seal);

  // --- Step 1: perform the asymmetric key exchange to reconstruct the common key
  //             used in the AEAD: this will allow the Authority to decrypt and
  //             obtain the plaintext --- delegateId --- in the next step
  const sealingKeyInfo /* S in paper */ = await primKDF(
    await primKEX(authorityPrivateKey, ephPublicKey),
    { outByteLength: schemeParams.paramAEADKeyInfoByteLength }
  );

  // --- Step 2: decrypt the ciphertext without verifying the AEAD auth tag (for the moment being)
  //             this reveals delegateId of the Signing Delegate
  const { plaintext: delegateId /* NB: still a candidate at this time */ } =
    await primAEADDecrypt(sealCiphertext, {
      keyinfo: sealingKeyInfo,
      abortOnBadTag: false,
      // as we only care about the plaintext, (and we do not know the AAD yet!)
      // we do not pass the AAD and do not check the auth tag at this moment
    });

  // --- Step 3: lookup delegateId for delegatePublicKey; this als implicitly
  //             verifies that a successful registration ceremony has taken place before
  const delegateLookupResult = await lookupDelegateInfo(delegateId, {
    schemeInstanceIdentity,
  });
  if (delegateLookupResult.kind === "not-found") {
    return {
      kind: "aborted",
      sensitiveAdditionalInformation: {
        reasonKind: "delegate-not-found",
        candidateDelegateId: delegateId,
      },
    };
  }
  const { delegatePublicKey } = delegateLookupResult;

  // --- Step 4: reconstruct the same delegateToken as in the registration ceremony
  //
  // NB: as our sole purpose for this step is to reconstruct the exact delegateToken,
  //     we can instead store the delegateToken along with delegatePublicKey
  //     in the Authority's database to trade storage for (1 KEX & 1+ KDF(s) worth of) calculation
  const K = await primKEX(authorityPrivateKey, delegatePublicKey);
  const delegateToken = await primKDF(concatS(K, delegateId, authoritySecret), {
    outByteLength: paramDelegateTokenByteLength,
  });

  // --- Step 5: reconstruct the payload hash keyed with delegateToken:
  //             we now have enough information to reconstruct the AEAD MAC (auth tag)
  const H = await primMAC(payload, {
    key: delegateToken,
    outputByteLength: paramHByteLength,
  });

  // --- Step 6: run AEAD again to check the AEAD MAC
  //
  // NB: we actually only need to verify the MAC but not re-decrypt.
  //     we are simply reusing primAEADDecrypt to save defining one more standalone primitive
  const { isTagValid } = await primAEADDecrypt(sealCiphertext, {
    keyinfo: sealingKeyInfo,
    abortOnBadTag: false,
    associatedData: H,
  });
  if (!isTagValid) {
    return {
      kind: "aborted",
      sensitiveAdditionalInformation: {
        reasonKind: "invalid-verification-tag",
        candidateDelegateId: delegateId,
        candidateDelegatePublicKey: delegatePublicKey,
      },
    };
  }

  // --- Step 7 (optional): check whether the delegateId has the privilege to make a seal
  //                        for the particular payload, if the application desires to
  let privilegeCheckResult: DelegatePrivilegeCheckResult;
  if (
    shouldCheckDelegatePrivilege &&
    checkDelegatePrivilege &&
    (privilegeCheckResult = await checkDelegatePrivilege({
      delegateId,
      payload,
      schemeInstanceIdentity,
    })) &&
    privilegeCheckResult.kind === "insufficient-delegate-privilege"
  ) {
    return {
      kind: "aborted",
      sensitiveAdditionalInformation: {
        reasonKind: "insufficient-delegate-privilege",
        delegateId,
        delegatePublicKey,
        detailedReason: privilegeCheckResult.detailedReason,
      },
    };
  }

  // --- and we are done and the validity of the seal has been established :)
  return {
    kind: "valid-seal",
    delegateId,
    delegatePublicKey,
  };
}
