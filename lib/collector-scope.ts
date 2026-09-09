export type CollectorScopeConfiguration = { awsRegion?: string; githubOrganization?: string; oktaOrigin?: string; cloudflareZoneIds?: string; browserUrls?: string };
export function collectorScopeCompatibility(configuration: CollectorScopeConfiguration, controls: string[], systems: string[]) {
  const hostname = (value?: string) => { try { const url = new URL(value || ""); return url.protocol === "https:" ? url.hostname : null; } catch { return null; } };
  const zones = (configuration.cloudflareZoneIds || "").split(",").map((item) => item.trim()).filter(Boolean);
  const browser = (configuration.browserUrls || "").split(",").map((item) => item.trim()).filter(Boolean);
  const definitions = [
    { provider: "aws", controls: ["2.2.1", "1.2.5"], systems: [configuration.awsRegion || "us-east-1"], known: true },
    { provider: "github", controls: ["6.3.2"], systems: configuration.githubOrganization ? [configuration.githubOrganization] : [], known: Boolean(configuration.githubOrganization) },
    { provider: "okta", controls: ["8.3.6", "7.2.5"], systems: hostname(configuration.oktaOrigin) ? [hostname(configuration.oktaOrigin)!] : [], known: Boolean(hostname(configuration.oktaOrigin)) },
    { provider: "cloudflare", controls: ["1.2.5"], systems: zones.length ? [`${zones.length} zones`] : [], known: zones.length > 0 },
    { provider: "browser", controls: ["2.2.1"], systems: [...new Set(browser.slice(0, 50).map(hostname).filter((item): item is string => Boolean(item)))], known: browser.length > 0 && browser.length <= 50 && browser.every((item) => Boolean(hostname(item))) },
  ];
  return definitions.map((item) => ({ ...item, missingControls: item.controls.filter((id) => !controls.includes(id)), missingSystems: item.systems.filter((name) => !systems.includes(name)), compatible: item.known && item.controls.every((id) => controls.includes(id)) && item.systems.every((name) => systems.includes(name)) }));
}
