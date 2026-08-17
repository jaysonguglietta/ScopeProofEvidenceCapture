export class SbomError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly status: number;
  constructor(message: string, code: string, retryable = false, status = 400) { super(message); this.code = code; this.retryable = retryable; this.status = status; }
}

export function isValidGitHubOwner(value: string): boolean { return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value) && !value.includes("--"); }
export function isValidRepositoryName(value: string): boolean { return /^[A-Za-z0-9_.-]{1,100}$/.test(value) && value !== "." && value !== ".."; }
export function isValidGitRef(value: string): boolean { return value.length >= 1 && value.length <= 200 && !value.startsWith("-") && !value.includes("..") && !value.includes("@{") && ![...value].some((character) => character.charCodeAt(0) <= 32 || "~^:?*[\\".includes(character)); }

export function parseGitHubRepositoryUrl(value: string): { owner: string; repository: string } {
  if (value !== value.trim() || value.length > 300) throw new SbomError("Enter an exact GitHub repository URL such as https://github.com/owner/repository.", "INVALID_REPOSITORY_URL");
  let url: URL;
  try { url = new URL(value); }
  catch { throw new SbomError("Enter an exact GitHub repository URL such as https://github.com/owner/repository.", "INVALID_REPOSITORY_URL"); }
  if (url.protocol !== "https:" || url.hostname !== "github.com" || url.port || url.username || url.password || url.search || url.hash || url.pathname.includes("%")) throw new SbomError("Only an exact HTTPS github.com repository URL is allowed.", "INVALID_REPOSITORY_URL");
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length !== 2) throw new SbomError("The GitHub URL must identify exactly one owner and repository.", "INVALID_REPOSITORY_URL");
  const owner = parts[0];
  const repository = parts[1].endsWith(".git") ? parts[1].slice(0, -4) : parts[1];
  if (!isValidGitHubOwner(owner) || !isValidRepositoryName(repository)) throw new SbomError("The GitHub repository owner or name is invalid.", "INVALID_REPOSITORY_URL");
  return { owner, repository };
}

export function validateOneTimeGitHubToken(value: string): string {
  if (value.length < 20 || value.length > 512 || value !== value.trim() || /\s/.test(value) || [...value].some((character) => character.charCodeAt(0) < 33 || character.charCodeAt(0) > 126)) throw new SbomError("Enter a valid one-time GitHub token.", "INVALID_GITHUB_TOKEN");
  return value;
}
