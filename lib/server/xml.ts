export function decodeXmlText(value: string): string {
  return value.replace(/&(?:amp|lt|gt|quot|apos|#(?:x[0-9a-fA-F]+|[0-9]+));/g, (entity) => {
    const named: Record<string, string> = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" };
    if (named[entity]) return named[entity];
    const hexadecimal = entity.startsWith("&#x");
    const codePoint = Number.parseInt(entity.slice(hexadecimal ? 3 : 2, -1), hexadecimal ? 16 : 10);
    return Number.isSafeInteger(codePoint) && codePoint >= 0 && codePoint <= 0x10ffff && !(codePoint >= 0xd800 && codePoint <= 0xdfff)
      ? String.fromCodePoint(codePoint) : "�";
  });
}
