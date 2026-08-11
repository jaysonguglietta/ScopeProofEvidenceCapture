export function stableJson(value: unknown): string {
  const ancestors = new WeakSet<object>();

  const assertValidUnicode = (text: string): void => {
    for (let index = 0; index < text.length; index += 1) {
      const code = text.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        if (index + 1 >= text.length) throw new TypeError("Canonical JSON cannot contain an unpaired Unicode surrogate.");
        const next = text.charCodeAt(index + 1);
        if (next < 0xdc00 || next > 0xdfff) throw new TypeError("Canonical JSON cannot contain an unpaired Unicode surrogate.");
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new TypeError("Canonical JSON cannot contain an unpaired Unicode surrogate.");
      }
    }
  };

  const serialize = (item: unknown): string => {
    if (item === null) return "null";
    if (typeof item === "boolean") return item ? "true" : "false";
    if (typeof item === "number") {
      if (!Number.isFinite(item)) throw new TypeError("Canonical JSON accepts only finite numbers.");
      return JSON.stringify(item);
    }
    if (typeof item === "string") {
      assertValidUnicode(item);
      return JSON.stringify(item);
    }
    if (typeof item !== "object") throw new TypeError(`Canonical JSON does not support ${typeof item} values.`);
    if (ancestors.has(item)) throw new TypeError("Canonical JSON cannot contain circular references.");

    ancestors.add(item);
    try {
      if (Array.isArray(item)) {
        const entries: string[] = [];
        for (let index = 0; index < item.length; index += 1) entries.push(serialize(item[index]));
        return `[${entries.join(",")}]`;
      }
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError("Canonical JSON accepts only plain objects and arrays.");
      if (Object.getOwnPropertySymbols(item).length > 0) throw new TypeError("Canonical JSON does not support symbol properties.");
      const record = item as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      return `{${keys.map((key) => {
        assertValidUnicode(key);
        return `${JSON.stringify(key)}:${serialize(record[key])}`;
      }).join(",")}}`;
    } finally {
      ancestors.delete(item);
    }
  };

  return serialize(value);
}
