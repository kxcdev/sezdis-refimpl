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
export type byte_string = Uint8Array;

/// regular byte string concatenation
export function concatR(...components: byte_string[]): byte_string {
  const buf = new Uint8Array(
    components.reduce((acc, comp) => acc + comp.length, 0)
  );
  let offset = 0;
  components.forEach((comp) => {
    buf.set(comp, offset);
    offset += comp.length;
  });
  return buf;
}

export function encodeByteStringAsHex(bytes: byte_string) {
  if (typeof Buffer === "function" && typeof Buffer.from === "function") {
    // if we have Node.js style Buffer
    return Buffer.from(bytes).toString("hex");
  } else {
    // otherwise we have to do the conv our own...
    let r = "";
    bytes.forEach((b) => (r += b.toString(16).padStart(2, "0")));
    return r;
  }
}

/// this method should be used instead of bytes.slice in case bytes is a Node.js Buffer
export function sliceByteString(
  bytes: byte_string,
  start?: number,
  end?: number
) {
  return Uint8Array.prototype.slice.call(bytes, start, end);
}
