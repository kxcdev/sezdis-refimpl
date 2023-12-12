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
