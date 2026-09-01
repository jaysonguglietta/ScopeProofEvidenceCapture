export type CatalogControl = Readonly<{
  id: string;
  title: string;
  requirement: string;
  defaultEvidence: string;
}>;

export type ControlCatalog = Readonly<{
  id: string;
  framework: string;
  version: string;
  title: string;
  controls: readonly CatalogControl[];
}>;

// This is intentionally a small, explicitly named operations catalog. It is
// not represented as the complete PCI DSS standard. Additional frameworks are
// only exposed after their exact licensed/versioned catalog is installed.
export const controlCatalogs: readonly ControlCatalog[] = [{
  id: "pci-dss-4.0.1-scopeproof-operations-v1",
  framework: "PCI DSS",
  version: "4.0.1",
  title: "PCI DSS 4.0.1 · Scopeproof operations catalog",
  controls: [
    { id: "1.2.5", requirement: "Requirement 1", title: "Maintain an inventory of network security controls", defaultEvidence: "Current network security control inventory and reviewed configuration." },
    { id: "2.2.1", requirement: "Requirement 2", title: "Configuration standards cover all system components", defaultEvidence: "Approved configuration standard and implementation evidence for each scoped component." },
    { id: "3.5.1.1", requirement: "Requirement 3", title: "Cryptographic keys are stored in the fewest locations", defaultEvidence: "Key inventory, location, custodian, and access-control evidence." },
    { id: "4.2.1", requirement: "Requirement 4", title: "Strong cryptography protects PAN during transmission", defaultEvidence: "Transport configuration proving approved protocol and cipher enforcement." },
    { id: "6.3.2", requirement: "Requirement 6", title: "Software inventory identifies custom and third-party components", defaultEvidence: "Versioned software inventory or SBOM bound to an immutable source revision." },
    { id: "7.2.5", requirement: "Requirement 7", title: "Application and system accounts are reviewed periodically", defaultEvidence: "Dated access review with population, reviewer, exceptions, and disposition." },
    { id: "8.3.6", requirement: "Requirement 8", title: "Authentication factors are protected from misuse", defaultEvidence: "Authentication policy and enforcement configuration for scoped identities." },
    { id: "10.4.1", requirement: "Requirement 10", title: "Audit logs are reviewed at least once daily", defaultEvidence: "Review schedule, alert configuration, and completed review record." },
    { id: "11.3.1", requirement: "Requirement 11", title: "Internal vulnerability scans occur every three months", defaultEvidence: "Authenticated scan results, scope, date, and remediation disposition." },
    { id: "12.3.1", requirement: "Requirement 12", title: "Targeted risk analyses document required elements", defaultEvidence: "Approved targeted risk analysis with scope, assumptions, frequency, and owner." },
  ],
}] as const;

export function findControlCatalog(id: string): ControlCatalog | undefined {
  return controlCatalogs.find((catalog) => catalog.id === id);
}

export function catalogControlMap(catalog: ControlCatalog): ReadonlyMap<string, CatalogControl> {
  return new Map(catalog.controls.map((control) => [control.id, control]));
}
