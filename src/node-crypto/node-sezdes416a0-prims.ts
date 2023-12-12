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
//
// SezDis416a0's choice of crypto primitives:
// SezDis416a0's choice of parameters:
// - AES key size: 128-bit (for both MAC and AEAD)
// - AES-GCM tag size: 128-bit
// - |A.secret| and |D.secret| : 2048-bit, wherein
//   - A refers to the Authority, and
//   - D refers to the Sealing Delegate
// - D.id : MAC(D.pub, key = KDF(A.secret, info = "D.id"))
// - |D.tok| : 2048-bit
// - H : 128-bit
// - KEYGEN : 256-bit of KDF output
// - S : 224-bit in total, 96 MSbits as IV, rest as AES key
// - Seal Representation : C || Eph.pub

import { SezDis416a0RequiredPrimitives } from "../sezdis-416a0";
import { aesCmac } from "./node-aes-cmac";
import { aesGcmDecrypt, aesGcmEncrypt } from "./node-aes-gcm";
import { hkdfSha512 } from "./node-hkdf";
import {
  x25519PublicFromPrivate,
  x25519ComputeSharedSecret,
} from "./node-x25519";

export const NodeSezDis416a0RequiredPrimitives: SezDis416a0RequiredPrimitives =
  {
    aesCmac,
    aesGcmEncrypt,
    aesGcmDecrypt,
    hkdfSha512,
    x25519PublicFromPrivate,
    x25519ComputeSharedSecret,
  };
