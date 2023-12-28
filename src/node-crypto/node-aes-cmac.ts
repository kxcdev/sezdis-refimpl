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
