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
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as _hacl_wasm from "hacl-wasm";

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as _AesCmac from "node-aes-cmac/lib/aes-cmac";

export type Hacl = {
  Curve25519_51: {
    ecdh: (
      scalar: Uint8Array,
      input: Uint8Array
    ) => Promise<[boolean, Uint8Array]>;
    scalarmult: (
      scalar: Uint8Array,
      input: Uint8Array
    ) => Promise<Uint8Array[]>;
    secret_to_public: (scalar: Uint8Array) => Promise<Uint8Array[]>;
  };
  Ed25519: {
    secret_to_public: (priv: Uint8Array) => Promise<Uint8Array[]>;
    sign: (priv: Uint8Array, message: Uint8Array) => Promise<Uint8Array[]>;
    verify: (
      pub: Uint8Array,
      message: Uint8Array,
      signature: Uint8Array
    ) => Promise<boolean[]>;
  };
};

export const HaclWasm = {
  getInitializedHaclModule: () =>
    _hacl_wasm.getInitializedHaclModule() as Promise<Hacl>,
};

export interface AesCmac {
  aesCmac(key: Buffer, message: Buffer): Buffer;
  generateSubkeys(key: Buffer): {
    subkey1: Buffer;
    subkey2: Buffer;
  };
}

export const AesCmac: AesCmac = _AesCmac;
