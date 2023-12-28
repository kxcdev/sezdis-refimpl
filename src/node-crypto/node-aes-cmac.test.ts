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
import { encodeByteStringAsHex } from "../basis";
import { aesCmac } from "./node-aes-cmac";

const hex = encodeByteStringAsHex;
function fromHex(data: string) {
  return Buffer.from(data, "hex");
}

describe("node-aes-cmac (hacl-wasm)", () => {
  // source: https://www.rfc-editor.org/rfc/rfc4493.html#section-4
  const key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");

  const testVectors = [
    {
      vectorName: "rfc4493sec4:len0",
      message: "",
      mac: "bb1d6929e95937287fa37d129b756746",
    },
    {
      vectorName: "rfc4493sec4:len16",
      message: "6bc1bee22e409f96e93d7e117393172a",
      mac: "070a16b46b4d4144f79bdd9dd04a287c",
    },
    {
      vectorName: "rfc4493sec4:len40",
      message:
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
      mac: "dfa66747de9ae63030ca32611497c827",
    },
    {
      vectorName: "rfc4493sec4:len64",
      message:
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      mac: "51f0bebf7e3b9d92fc49741779363cfe",
    },
  ];

  testVectors.forEach(({ vectorName, message, mac }) => {
    test("test vector " + vectorName, async () => {
      expect(
        hex(
          await aesCmac(fromHex(message), {
            key,
            outputByteLength: 128 / 8,
          })
        )
      ).toBe(mac);
      expect(
        hex(
          await aesCmac(fromHex(message), {
            key,
            outputByteLength: 64 / 8,
          })
        )
      ).toBe(mac.substring(0, (64 / 8) * 2));
    });
  });
});
