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
import { HaclWasm } from "./node-imported";

async function getHaclCurve25519() {
  return (await HaclWasm.getInitializedHaclModule()).Curve25519_51;
}

function checkKeySize(
  funcName: string,
  keyName: string,
  keyByteLength: number
) {
  if (keyByteLength !== 256 / 8) {
    throw new Error(
      `${funcName} - ${keyName} must be 256-bit (i.e. 32 bytes): but got ${keyByteLength} bytes`
    );
  }
}

export async function x25519PublicFromPrivate(
  privateKey: byte_string
): Promise<byte_string> {
  checkKeySize("x25519PublicFromPrivate", "private key", privateKey.length);
  return (await (await getHaclCurve25519()).secret_to_public(privateKey))[0];
}

export async function x25519ComputeSharedSecret(
  privateKey: byte_string,
  peerPublicKey: byte_string
): Promise<byte_string> {
  checkKeySize("x25519ComputeSharedSecret", "private key", privateKey.length);
  checkKeySize(
    "x25519ComputeSharedSecret",
    "peer public key",
    peerPublicKey.length
  );

  return (await (await getHaclCurve25519()).ecdh(privateKey, peerPublicKey))[1];
}
