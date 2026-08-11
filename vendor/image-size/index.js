const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const MAX_DIMENSION = 65_535;

function fail(message) {
  throw new TypeError(`Unsupported or malformed image metadata: ${message}`);
}

function bytes(input) {
  if (!(input instanceof Uint8Array)) fail("input must be a byte array");
  if (input.byteLength < 10 || input.byteLength > MAX_INPUT_BYTES) fail("input size is outside the accepted range");
  return input;
}

function dimensions(width, height, type) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 || width > MAX_DIMENSION || height > MAX_DIMENSION) fail("dimensions are invalid");
  return { width, height, type };
}

function ascii(input, offset, length) {
  if (offset < 0 || length < 0 || offset + length > input.length) fail("truncated signature");
  return String.fromCharCode(...input.subarray(offset, offset + length));
}

function u16be(input, offset) {
  if (offset + 2 > input.length) fail("truncated 16-bit value");
  return (input[offset] << 8) | input[offset + 1];
}

function u16le(input, offset) {
  if (offset + 2 > input.length) fail("truncated 16-bit value");
  return input[offset] | (input[offset + 1] << 8);
}

function u24le(input, offset) {
  if (offset + 3 > input.length) fail("truncated 24-bit value");
  return input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16);
}

function u32be(input, offset) {
  if (offset + 4 > input.length) fail("truncated 32-bit value");
  return ((input[offset] * 0x1000000) + (input[offset + 1] << 16) + (input[offset + 2] << 8) + input[offset + 3]) >>> 0;
}

function png(input) {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (!signature.every((value, index) => input[index] === value)) return null;
  if (u32be(input, 8) !== 13 || ascii(input, 12, 4) !== "IHDR") fail("invalid PNG header");
  return dimensions(u32be(input, 16), u32be(input, 20), "png");
}

function gif(input) {
  const signature = ascii(input, 0, 6);
  if (signature !== "GIF87a" && signature !== "GIF89a") return null;
  return dimensions(u16le(input, 6), u16le(input, 8), "gif");
}

function ico(input) {
  if (u16le(input, 0) !== 0 || ![1, 2].includes(u16le(input, 2))) return null;
  if (u16le(input, 4) < 1 || input.length < 22) fail("invalid ICO directory");
  return dimensions(input[6] || 256, input[7] || 256, "ico");
}

function jpeg(input) {
  if (input[0] !== 0xff || input[1] !== 0xd8) return null;
  const startOfFrame = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
  let offset = 2;
  while (offset < input.length) {
    while (offset < input.length && input[offset] === 0xff) offset += 1;
    if (offset >= input.length) fail("truncated JPEG marker");
    const marker = input[offset++];
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    const length = u16be(input, offset);
    if (length < 2 || offset + length > input.length) fail("invalid JPEG segment length");
    if (startOfFrame.has(marker)) {
      if (length < 7) fail("truncated JPEG frame");
      return dimensions(u16be(input, offset + 3), u16be(input, offset + 1), "jpg");
    }
    offset += length;
  }
  fail("JPEG dimensions were not found");
}

function webp(input) {
  if (ascii(input, 0, 4) !== "RIFF" || ascii(input, 8, 4) !== "WEBP") return null;
  if (input.length < 30) fail("truncated WebP header");
  const chunk = ascii(input, 12, 4);
  if (chunk === "VP8X") return dimensions(1 + u24le(input, 24), 1 + u24le(input, 27), "webp");
  if (chunk === "VP8 ") {
    if (input[23] !== 0x9d || input[24] !== 0x01 || input[25] !== 0x2a) fail("invalid VP8 frame header");
    return dimensions(u16le(input, 26) & 0x3fff, u16le(input, 28) & 0x3fff, "webp");
  }
  if (chunk === "VP8L") {
    if (input[20] !== 0x2f) fail("invalid VP8L frame header");
    const packed = (input[21] | (input[22] << 8) | (input[23] << 16) | (input[24] << 24)) >>> 0;
    return dimensions((packed & 0x3fff) + 1, ((packed >>> 14) & 0x3fff) + 1, "webp");
  }
  fail("unsupported WebP chunk");
}

export function imageSize(input) {
  const value = bytes(input);
  return png(value) ?? gif(value) ?? ico(value) ?? jpeg(value) ?? webp(value) ?? fail("only PNG, JPEG, GIF, WebP, and ICO are accepted");
}

export default imageSize;
