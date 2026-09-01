export type PackagePublicationState = Readonly<{
  status: string;
  r2Key: string | null;
  sha256: string | null;
  signature: string | null;
  evidenceCount: number;
  excludedCount: number;
  encryptionKeyId: string;
  byteSize: number;
  completedAt: string | null;
  expiresAt: string;
}>;

export type ExpectedPackagePublication = Readonly<{
  r2Key: string;
  sha256: string;
  signature: string;
  evidenceCount: number;
  excludedCount: number;
  encryptionKeyId: string;
  byteSize: number;
  completedAt: string;
  expiresAt: string;
}>;

export type PackagePublicationDisposition = "committed" | "referenced" | "unreferenced";

/**
 * Classify only an authoritative post-write database read. A mismatched row
 * that still names the candidate is never deletion proof; preserving an
 * orphan is safer than deleting a package that may have won an ambiguous CAS.
 */
export function classifyPackagePublication(
  state: PackagePublicationState | null,
  candidateR2Key: string,
  expected: ExpectedPackagePublication | null,
): PackagePublicationDisposition {
  if (state && expected
    && state.status === "ready"
    && state.r2Key === expected.r2Key
    && state.sha256 === expected.sha256
    && state.signature === expected.signature
    && state.evidenceCount === expected.evidenceCount
    && state.excludedCount === expected.excludedCount
    && state.encryptionKeyId === expected.encryptionKeyId
    && state.byteSize === expected.byteSize
    && state.completedAt === expected.completedAt
    && state.expiresAt === expected.expiresAt) return "committed";
  if (state?.r2Key === candidateR2Key) return "referenced";
  return "unreferenced";
}
