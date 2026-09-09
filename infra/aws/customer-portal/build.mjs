import { mkdir, copyFile, writeFile, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validatePortalConfiguration } from "./security.mjs";

// Only public identifiers/HTTPS endpoints. No AWS keys or client secrets.
const raw = process.env.SCOPEPROOF_PORTAL_CONFIG_JSON;
if (!raw || raw.length > 200000) throw new Error("Set SCOPEPROOF_PORTAL_CONFIG_JSON to the reviewed hostname-keyed public outputs. Empty builds are forbidden.");
const configs = JSON.parse(raw);
if (!configs || Array.isArray(configs) || Object.keys(configs).length < 1 || Object.keys(configs).length > 100) throw new Error("Provide 1–100 explicit tenant configurations.");
for (const [hostname, config] of Object.entries(configs)) validatePortalConfiguration(config, `https://${hostname}`);
const output = resolve(process.argv[2] || ".scopeproof-portal");
const source = fileURLToPath(new URL(".", import.meta.url));
await mkdir(output, { recursive: true });
for (const file of ["index.html", "portal.css", "portal.mjs", "security.mjs"]) await copyFile(resolve(source, file), resolve(output, file));
await mkdir(resolve(output, "auth/callback"), { recursive: true });
await copyFile(resolve(source, "index.html"), resolve(output, "auth/callback/index.html"));
await writeFile(resolve(output, "tenant-config.json"), JSON.stringify(configs, null, 2));
// The CDK app sets mandatory response headers too. This exact-origin manifest\n// is supplied for an operator-reviewed manual hosting package.
const origins = [...new Set(Object.values(configs).flatMap((config) => [config.apiOrigin, config.oauthOrigin]))];
const headers = ["customHeaders:", "  - pattern: '**/*'", "    headers:",
  "      - key: Content-Security-Policy", `        value: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self' ${origins.join(" ")} https://*.amazonaws.com https://*.amazonaws.com.cn; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"`,
  "      - key: Referrer-Policy", "        value: no-referrer", "      - key: X-Content-Type-Options", "        value: nosniff", "      - key: Cache-Control", "        value: no-store", "      - key: Strict-Transport-Security", "        value: max-age=31536000; includeSubDomains"].join("\n");
await writeFile(resolve(output, "customHttp.yml"), headers + "\n");
await writeFile(resolve(output, "source-contract.json"), JSON.stringify({ schema: 1, surface: "aws-customer-portal", configurationContainsSecrets: false, documentation: "docs/AWS_CUSTOMER_PORTAL.md", securityModule: (await readFile(resolve(source, "security.mjs"))).byteLength }, null, 2));
console.log("Built static AWS portal; no upload or deployment performed.");
