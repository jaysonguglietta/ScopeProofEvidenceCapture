export async function boundedFetch(input: string | URL, init: RequestInit, policy: { label: string; allowedOrigins: readonly string[]; maximumBytes: number; timeoutMs: number }): Promise<Response> {
  const url = new URL(input.toString());
  if (!policy.allowedOrigins.includes(url.origin) || url.username || url.password || url.protocol !== "https:") throw new Error(`${policy.label} uses an unapproved outbound origin.`);
  const response = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(policy.timeoutMs) });
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > policy.maximumBytes) throw new Error(`${policy.label} returned an oversized response.`);
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > policy.maximumBytes) {
        await reader.cancel("response size limit exceeded");
        throw new Error(`${policy.label} returned an oversized response.`);
      }
      chunks.push(value);
    }
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}
