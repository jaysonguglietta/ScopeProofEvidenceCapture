/** Serializes one spreadsheet-safe CSV field. Signed JSON remains authoritative. */
export function csvCell(value: unknown): string {
  const original = String(value ?? "");
  let index = 0;
  while (index < original.length && original.charCodeAt(index) <= 0x20) index += 1;
  const neutralized = "=+-@".includes(original[index] || "") ? `'${original}` : original;
  return `"${neutralized.replaceAll('"', '""')}"`;
}
