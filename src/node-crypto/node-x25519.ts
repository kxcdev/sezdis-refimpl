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
