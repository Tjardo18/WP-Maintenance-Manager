export type SiteStatus = "healthy" | "updates" | "attention" | "problem" | "unreachable" | "unscanned";
export type AuthMethod = "keyFile" | "password";
export type StepStatus = "pending" | "running" | "success" | "warning" | "failed" | "skipped";

export interface Site {
  id: string;
  name: string;
  url: string;
  sshHost: string;
  sshPort: number;
  sshUsername: string;
  authMethod: AuthMethod;
  keyPath?: string | null;
  wordpressPath: string;
  pinnedHostKey?: string | null;
  status: SiteStatus;
  wordpressVersion?: string | null;
  phpVersion?: string | null;
  updateCount: number;
  securityStatus?: string | null;
  lastScanAt?: string | null;
  lastMaintenanceAt?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SiteInput {
  id?: string;
  name: string;
  url: string;
  sshHost: string;
  sshPort: number;
  sshUsername: string;
  authMethod: AuthMethod;
  keyPath?: string | null;
  wordpressPath: string;
  credentialSecret?: string;
}

export interface TechnicalError { category: string; userMessage: string; technicalDetails?: string; retryable: boolean }
export interface ConnectionTestResult {
  success: boolean;
  steps: Array<{ key: string; label: string; status: StepStatus; detail?: string }>;
  fingerprint?: string;
  requiresHostKeyAcceptance: boolean;
  wordpressVersion?: string;
  phpVersion?: string;
  wpCliVersion?: string;
  detectedUrl?: string;
  error?: TechnicalError;
}

export interface ScanCheck { key: string; label: string; status: StepStatus; summary: string; findings: Finding[] }
export type ChecksumStatus = "modified" | "missing" | "unexpected" | "scan_error";
export interface Finding { id?: string; category: string; severity: "info" | "attention" | "problem"; title: string; detail: string; path?: string; checksumStatus?: ChecksumStatus; observedAt?: string }
export interface FilePreview { finding: Finding; fileName: string; relativePath: string; sizeBytes: number; modifiedAt?: string; fileType: string; extension?: string; textContent?: string; binary: boolean; truncated: boolean }
export interface ChecksumDeleteFailure { findingId: string; path?: string; error: TechnicalError }
export interface ChecksumDeleteResult { requested: number; deleted: number; deletedPaths: string[]; failures: ChecksumDeleteFailure[]; scan?: ScanResult; rescanError?: TechnicalError }
export interface WordPressUser { id: number; username: string; displayName: string; email: string; roles: string[]; registeredAt: string }
export interface WordPressRole { role: string; name: string }
export interface WordPressUsersData { users: WordPressUser[]; roles: WordPressRole[]; multisite: boolean }
export interface WordPressUserUpdateInput { userId: number; displayName: string; email: string; role?: string }
export interface WordPressUserDeleteInput { userId: number; reassignTo?: number; deleteContent: boolean }
export interface ScanResult { id: string; siteId: string; startedAt: string; finishedAt: string; status: SiteStatus; checks: ScanCheck[]; truncated: boolean }
export interface UpdateItem { kind: "core" | "plugin" | "theme" | "language"; slug: string; name: string; currentVersion: string; newVersion: string; status: string }
export interface MaintenanceStep { key: string; label: string; status: StepStatus; detail?: string }
export interface MaintenanceRun { id: string; siteId: string; siteName?: string; startedAt: string; finishedAt?: string; status: StepStatus; durationMs?: number; backupPath?: string; steps: MaintenanceStep[]; beforeVersions?: string; afterVersions?: string }
export interface BulkScanProgress { total: number; completed: number; activeSites: string[]; failedSites: string[] }
export interface BulkScanResult { total: number; completed: number; cancelled: boolean; failures: Array<{ siteId: string; siteName: string; error: TechnicalError }> }
export interface AppSettings { scanConcurrency: number }
export interface AuthStatus { configured: boolean; authenticated: boolean; idleTimeoutMinutes: number; retryAfterSeconds: number }
export interface LoginResult { sessionToken: string; idleTimeoutMinutes: number }
export interface PasswordChangeInput { currentPassword: string; newPassword: string }
export interface AuditEvent { id: string; siteId?: string; actionType: string; target: string; status: "success" | "failed"; details?: string; createdAt: string }
