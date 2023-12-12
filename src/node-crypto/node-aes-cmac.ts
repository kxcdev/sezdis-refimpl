import { AesCmac } from "./node-imported";
import { byte_string, sliceByteString } from "../basis";

export async function aesCmac(
  data: byte_string,
  params: {
    key: byte_string;
    outputByteLength: number;
  }
): Promise<byte_string> {
  const { key, outputByteLength } = params;
  const keyByteLength = key.byteLength;

  switch (keyByteLength) {
    case 16 /* 128-bit */:
    case 24 /* 192-bit */:
    case 32 /* 256-bit */:
      break;
    default:
      throw new Error("bad key byte length for AES-CMAC: " + keyByteLength);
  }

  if (outputByteLength > 128 / 8) {
    throw new Error("bad output byte length for AES-CMAC: " + outputByteLength);
  }

  const buf: Buffer = AesCmac.aesCmac(Buffer.from(key), Buffer.from(data));
  return sliceByteString(buf, 0, outputByteLength);
}
