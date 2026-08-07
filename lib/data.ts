import type { CollectionRun, Control, Evidence, Finding } from "./types";

export const controls: Control[] = [
  { id: "1.2.5", requirement: "Req. 1", title: "Maintain an inventory of network security controls", owner: "Network Security", status: "Covered", evidenceCount: 6, automation: 100, nextDue: "Sep 12", systems: ["AWS", "Cloudflare"] },
  { id: "2.2.1", requirement: "Req. 2", title: "Configuration standards cover all system components", owner: "Platform Engineering", status: "Partial", evidenceCount: 4, automation: 75, nextDue: "Aug 16", systems: ["GitHub", "AWS"] },
  { id: "3.5.1.1", requirement: "Req. 3", title: "Cryptographic keys are stored in the fewest locations", owner: "Security Engineering", status: "Covered", evidenceCount: 8, automation: 100, nextDue: "Oct 01", systems: ["AWS KMS"] },
  { id: "4.2.1", requirement: "Req. 4", title: "Strong cryptography protects PAN during transmission", owner: "Application Security", status: "Covered", evidenceCount: 5, automation: 100, nextDue: "Sep 28", systems: ["AWS ALB", "Cloudflare"] },
  { id: "6.3.2", requirement: "Req. 6", title: "Software inventory identifies custom and third-party components", owner: "Application Security", status: "Partial", evidenceCount: 3, automation: 67, nextDue: "Aug 10", systems: ["GitHub", "Snyk"] },
  { id: "7.2.5", requirement: "Req. 7", title: "Application and system accounts are reviewed periodically", owner: "Identity & Access", status: "Gap", evidenceCount: 1, automation: 25, nextDue: "Overdue", systems: ["Okta", "AWS IAM"] },
  { id: "8.3.6", requirement: "Req. 8", title: "Authentication factors are protected from misuse", owner: "Identity & Access", status: "Covered", evidenceCount: 7, automation: 100, nextDue: "Nov 04", systems: ["Okta"] },
  { id: "10.4.1", requirement: "Req. 10", title: "Audit logs are reviewed at least once daily", owner: "Security Operations", status: "Partial", evidenceCount: 5, automation: 80, nextDue: "Today", systems: ["Datadog", "AWS"] },
  { id: "11.3.1", requirement: "Req. 11", title: "Internal vulnerability scans occur every three months", owner: "Security Operations", status: "Covered", evidenceCount: 9, automation: 100, nextDue: "Oct 18", systems: ["Tenable"] },
  { id: "12.3.1", requirement: "Req. 12", title: "Targeted risk analyses document required elements", owner: "GRC", status: "Gap", evidenceCount: 0, automation: 0, nextDue: "Overdue", systems: ["Manual"] },
];

export const evidence: Evidence[] = [
  {
    id: "EV-1048", title: "Production WAF managed rules", control: "1.2.5", requirement: "Req. 1", type: "Screenshot", source: "Cloudflare", system: "edge-production", capturedAt: "Aug 7, 2026 · 10:42 AM", expiresAt: "Nov 5, 2026", status: "Needs review", collector: "Browser capture", checksum: "sha256:8a1c…4e92", description: "Managed ruleset overview showing OWASP and Cloudflare managed rules enabled for the production zone.", accent: "blue", tags: ["Quarterly", "Production", "Auto-redacted"]
  },
  {
    id: "EV-1047", title: "TLS policy — production load balancer", control: "4.2.1", requirement: "Req. 4", type: "Configuration", source: "AWS", system: "payments-alb", capturedAt: "Aug 7, 2026 · 10:39 AM", expiresAt: "Nov 5, 2026", status: "Approved", collector: "AWS Config", checksum: "sha256:92fb…0c12", description: "Listener policy confirms TLS 1.2 minimum with an approved cipher suite.", code: "resource \"aws_lb_listener\" \"payments_https\" {\n  port     = 443\n  protocol = \"HTTPS\"\n  ssl_policy = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"\n}", language: "HCL", accent: "emerald", tags: ["Continuous", "Production", "Infrastructure as code"]
  },
  {
    id: "EV-1046", title: "MFA enforcement policy", control: "8.3.6", requirement: "Req. 8", type: "Screenshot", source: "Okta", system: "workforce-identity", capturedAt: "Aug 7, 2026 · 10:33 AM", expiresAt: "Nov 5, 2026", status: "Approved", collector: "Browser capture", checksum: "sha256:287d…ba41", description: "Global session policy requiring phishing-resistant MFA for privileged groups.", accent: "violet", tags: ["Quarterly", "Identity", "Auto-redacted"]
  },
  {
    id: "EV-1045", title: "Daily log review monitor", control: "10.4.1", requirement: "Req. 10", type: "Code", source: "GitHub", system: "security-detections", capturedAt: "Aug 7, 2026 · 10:28 AM", expiresAt: "Sep 6, 2026", status: "Needs review", collector: "GitHub API", checksum: "sha256:df54…93ad", description: "Detection-as-code rule verifying daily review coverage for cardholder data environment logs.", code: "schedule: \"0 7 * * *\"\nquery: >-\n  service:payments AND\n  status:(error OR denied)\nnotify: security-operations", language: "YAML", accent: "amber", tags: ["Daily", "CDE", "Code evidence"]
  },
  {
    id: "EV-1044", title: "IAM access review export", control: "7.2.5", requirement: "Req. 7", type: "Report", source: "AWS", system: "production-account", capturedAt: "Aug 7, 2026 · 10:21 AM", expiresAt: "Aug 14, 2026", status: "Expiring", collector: "AWS IAM", checksum: "sha256:92ec…60f1", description: "Privileged role assignments and last-used timestamps. Two identities require owner confirmation.", accent: "amber", tags: ["Quarterly", "Restricted", "Review required"]
  },
  {
    id: "EV-1043", title: "Container vulnerability scan", control: "11.3.1", requirement: "Req. 11", type: "Report", source: "Tenable", system: "checkout-api", capturedAt: "Aug 6, 2026 · 11:54 PM", expiresAt: "Nov 4, 2026", status: "Approved", collector: "Tenable API", checksum: "sha256:6cb0…109f", description: "Authenticated scan report for the production checkout service container and host.", accent: "emerald", tags: ["Quarterly", "Production", "Signed report"]
  }
];

export const runs: CollectionRun[] = [
  { id: "RUN-2981", source: "PCI daily evidence sweep", startedAt: "Today · 10:20 AM", status: "Completed", artifacts: 18, controls: 9, duration: "4m 38s" },
  { id: "RUN-2980", source: "AWS production accounts", startedAt: "Today · 7:00 AM", status: "Partial", artifacts: 24, controls: 12, duration: "7m 12s", note: "1 account unreachable" },
  { id: "RUN-2979", source: "GitHub protected branches", startedAt: "Yesterday · 6:00 PM", status: "Completed", artifacts: 11, controls: 4, duration: "2m 03s" },
  { id: "RUN-2978", source: "Okta identity policies", startedAt: "Yesterday · 3:30 PM", status: "Completed", artifacts: 8, controls: 5, duration: "1m 46s" },
  { id: "RUN-2977", source: "Cloudflare zones", startedAt: "Aug 6 · 10:00 AM", status: "Failed", artifacts: 0, controls: 0, duration: "12s", note: "Credential expired" },
];

export const findings: Finding[] = [
  { id: "FND-028", title: "Quarterly privileged access review is incomplete", control: "7.2.5", severity: "High", owner: "Maya Chen", due: "Aug 12", status: "In progress" },
  { id: "FND-027", title: "Cloudflare collector credential has expired", control: "1.2.5", severity: "Medium", owner: "Andre Silva", due: "Aug 9", status: "Open" },
  { id: "FND-026", title: "Two repositories lack an approved software inventory", control: "6.3.2", severity: "Medium", owner: "Priya Shah", due: "Aug 16", status: "Open" },
  { id: "FND-025", title: "Targeted risk analysis missing for log review cadence", control: "12.3.1", severity: "Low", owner: "Elena Torres", due: "Aug 23", status: "Accepted" },
];

export const requirementCoverage = [
  { name: "Network security", req: "1", value: 94 },
  { name: "Secure configurations", req: "2", value: 81 },
  { name: "Stored account data", req: "3", value: 100 },
  { name: "Data in transit", req: "4", value: 100 },
  { name: "Secure development", req: "6", value: 72 },
  { name: "Access control", req: "7", value: 64 },
  { name: "Authentication", req: "8", value: 96 },
  { name: "Logging & monitoring", req: "10", value: 86 },
  { name: "Security testing", req: "11", value: 90 },
  { name: "Policies & programs", req: "12", value: 58 },
];
