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
import { aesGcmDecrypt, aesGcmEncrypt } from "./node-aes-gcm";
import { byte_string, sliceByteString } from "../basis";

function copy(bytes: byte_string): byte_string {
  return sliceByteString(bytes);
}

describe("node-aes-gcm", () => {
  function bytesAsString(bytes: byte_string) {
    return Buffer.from(bytes).toString("hex");
  }

  function expectDecryptionResult(
    actual: [byte_string, boolean],
    expected: [byte_string, boolean]
  ) {
    function tr(x: [byte_string, boolean]) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const y: [string, boolean] = [...x];
      y[0] = bytesAsString(x[0]);
      return y;
    }
    return expect(tr(actual)).toStrictEqual(tr(expected));
  }

  function runSimpleTestsOnMessage(
    message: byte_string,
    opts?: {
      key?: byte_string;
      iv?: byte_string;
      tagBitLength?: number;
      associatedData?: byte_string;
    }
  ) {
    it("simpleTestsOnMessage: " + message, async () => {
      const key = opts?.key ?? new Uint8Array(Array(128 / 8).fill(0));
      const iv = opts?.iv ?? new Uint8Array(Array(96 / 8).fill(1));
      const tagBitLength = opts?.tagBitLength ?? 128;
      const associatedData = opts?.associatedData;

      const ciphertext = await aesGcmEncrypt(message, {
        key,
        iv,
        tagBitLength,
        associatedData,
      });
      expect(ciphertext.length).toBe(message.length + tagBitLength / 8);

      const decrypted = await aesGcmDecrypt(ciphertext, {
        key,
        iv,
        tagBitLength,
        associatedData,
        abortOnBadTag: true,
      });
      expectDecryptionResult(decrypted, [message, true]);

      const ciphertextBadTag = copy(ciphertext);
      ciphertextBadTag[message.length] ^= 0x1a;

      await expect(async () => {
        await aesGcmDecrypt(ciphertextBadTag, {
          key,
          iv,
          tagBitLength,
          associatedData,
          abortOnBadTag: true,
        });
      }).rejects.toThrow();

      expectDecryptionResult(
        await aesGcmDecrypt(ciphertextBadTag, {
          key,
          iv,
          tagBitLength,
          associatedData,
          abortOnBadTag: false,
        }),
        [message, false]
      );

      if (message.length > 0) {
        const ciphertextBadMessage = copy(ciphertext);
        ciphertextBadMessage[0] ^= 0x1a;

        await expect(async () => {
          await aesGcmDecrypt(ciphertextBadMessage, {
            key,
            iv,
            tagBitLength,
            associatedData,
            abortOnBadTag: true,
          });
        }).rejects.toThrow();

        const [decryptedBadMessage, decryptedBadMessageValid] =
          await aesGcmDecrypt(ciphertextBadMessage, {
            key,
            iv,
            tagBitLength,
            associatedData,
            abortOnBadTag: false,
          });
        expect(bytesAsString(decryptedBadMessage)).not.toBe(
          bytesAsString(message)
        );
        expect(decryptedBadMessageValid).toBe(false);
      }

      if (associatedData != null && associatedData.length > 0) {
        const badAssociatedData = copy(associatedData);
        badAssociatedData[0] ^= 0x1a;

        await expect(async () => {
          await aesGcmDecrypt(ciphertext, {
            key,
            iv,
            tagBitLength,
            associatedData: badAssociatedData,
            abortOnBadTag: true,
          });
        }).rejects.toThrow();

        const decryptedResultBadAAD = await aesGcmDecrypt(ciphertext, {
          key,
          iv,
          tagBitLength,
          associatedData: badAssociatedData,
          abortOnBadTag: false,
        });
        expectDecryptionResult(decryptedResultBadAAD, [message, false]);
      }
    });
  }

  describe("encrypts and decrypts", () => {
    const nullMessage = new Uint8Array([]);
    const shortMessage = Buffer.from("hello?", "utf8");
    const longMessage = Buffer.from(
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum",
      "utf8"
    );

    describe("without aad", () => {
      [nullMessage, shortMessage, longMessage].forEach((msg) =>
        runSimpleTestsOnMessage(msg)
      );

      [nullMessage, shortMessage, longMessage].forEach((msg) =>
        runSimpleTestsOnMessage(msg, {
          tagBitLength: 96,
        })
      );
    });

    describe("with aad", () => {
      [nullMessage, shortMessage, longMessage].forEach((msg) =>
        runSimpleTestsOnMessage(msg, {
          associatedData: shortMessage,
        })
      );
    });
  });
});
