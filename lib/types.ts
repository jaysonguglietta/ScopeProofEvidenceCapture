export type EvidenceType = "Screenshot" | "Code" | "Configuration" | "Report";
export type EvidenceStatus = "Approved" | "Needs review" | "Expiring" | "Failed";
export type ControlStatus = "Covered" | "Partial" | "Gap";

export interface Evidence {
  id: string;
  title: string;
  control: string;
  framework?: string;
  requirement: string;
  type: EvidenceType;
  source: string;
  system: string;
  capturedAt: string;
  expiresAt: string;
  status: EvidenceStatus;
  collector: string;
  checksum: string;
  description: string;
  code?: string;
  language?: string;
  accent?: "blue" | "violet" | "emerald" | "amber";
  tags: string[];
  owner?: string;
  environment?: string;
  assessmentPeriod?: string;
  mappedControls?: Array<{ framework: string; controlID: string; relationship: string }>;
  jiraIssueKey?: string;
  jiraIssueURL?: string;
}

export interface Control {
  id: string;
  requirement: string;
  title: string;
  owner: string;
  status: ControlStatus;
  evidenceCount: number;
  automation: number;
  nextDue: string;
  systems: string[];
}

export interface CollectionRun {
  id: string;
  source: string;
  startedAt: string;
  status: "Completed" | "Partial" | "Running" | "Failed";
  artifacts: number;
  controls: number;
  duration: string;
  note?: string;
}

export interface Finding {
  id: string;
  title: string;
  control: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  owner: string;
  due: string;
  status: "Open" | "In progress" | "Accepted" | "Resolved";
}
