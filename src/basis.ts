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
