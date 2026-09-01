const extensionByType: Record<string, string> = {
  "application/json": ".json",
  "application/xml": ".xml",
  "application/x-yaml": ".yaml",
  "application/yaml": ".yaml",
  "image/png": ".png",
  "text/csv": ".csv",
  "text/markdown": ".md",
  "text/plain": ".txt",
  "text/xml": ".xml",
  "text/yaml": ".yaml",
};

export const SAFE_MANUAL_EVIDENCE_TYPES = new Set(Object.keys(extensionByType).filter((type) => type !== "image/png"));

export function evidenceResponseHeaders(id: string, storedContentType: string, inlineRequested: boolean): Headers {
  const contentType = storedContentType.split(";", 1)[0].trim().toLowerCase();
  const inline = inlineRequested && contentType === "image/png";
  const extension = extensionByType[contentType] || ".bin";
  return new Headers({
    // Anything other than the exact PNG workflow is downloaded as inert bytes.
    // The console still obtains it with fetch() and renders decoded text through React.
    "content-type": contentType === "image/png" ? "image/png" : "application/octet-stream",
    "content-disposition": `${inline ? "inline" : "attachment"}; filename="${id}${extension}"`,
    "content-security-policy": "default-src 'none'; sandbox",
    "cross-origin-resource-policy": "same-origin",
    "x-content-type-options": "nosniff",
    "cache-control": "private, no-store",
  });
}
