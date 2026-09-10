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

export interface TechnicalError { errorId?: string; category: string; userMessage: string; technicalDetails?: string; retryable: boolean }
export type ErrorSeverity = "warning" | "error" | "critical";
export type ErrorCategory = "network" | "dns" | "connection_timeout" | "ssh_authentication" | "ssh_host_key" | "ssh_channel" | "ssh_command" | "wp_cli" | "database" | "http" | "filesystem" | "backup" | "update" | "parse" | "authentication" | "application" | "unknown";
export interface ErrorLogRecord { id: string; createdAt: string; severity: ErrorSeverity; category: ErrorCategory; siteId?: string; siteName?: string; action: string; summary: string; technicalDetails?: string; exitCode?: number; causeChain: string[]; durationMs?: number; retryable: boolean }
export interface ErrorLogFilter { siteId?: string; category?: ErrorCategory; severity?: ErrorSeverity; from?: string; to?: string; query?: string; limit?: number; offset?: number }
export interface ErrorLogPage { records: ErrorLogRecord[]; total: number; limit: number; offset: number }
export interface TerminalChallengeInfo { challengeToken: string; expiresInSeconds: number }
export interface TerminalConnectionInfo { sessionId: string; authorizationToken: string; siteId: string; startPath: string; columns: number; rows: number }
export interface TerminalOutputEvent { sessionId: string; dataBase64: string }
export interface TerminalStatusEvent { sessionId: string; status: "connected" | "disconnected" | "failed"; message?: string; error?: TechnicalError }
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

export interface ScanCheck { key: string; label: string; status: StepStatus; summary: string; technicalDetails?: string; findings: Finding[] }
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
export type CoreOperationKind = "repair" | "update";
export interface CoreOperationInfo { currentVersion: string; locale: string; wordpressPath: string; availableVersion?: string; diskAvailableMb: number }
export interface CoreOperationResult { run: MaintenanceRun; scan?: ScanResult; updatesAfter: UpdateItem[]; currentVersion: string }
export interface ScanResult { id: string; siteId: string; startedAt: string; finishedAt: string; status: SiteStatus; checks: ScanCheck[]; truncated: boolean }
export type ScanJobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export interface ScanJobStep { key: string; label: string; status: StepStatus; startedAt?: string; durationMs?: number; detail?: string }
export interface ScanJobState { id: string; jobType: string; siteId: string; siteName: string; status: ScanJobStatus; createdAt: string; startedAt?: string; finishedAt?: string; currentStep?: string; completedSteps: number; totalSteps: number; cancellationRequested: boolean; resultScanId?: string; error?: TechnicalError; steps: ScanJobStep[] }
export interface BulkScanStart { jobs: ScanJobState[] }
export interface UpdateItem { kind: "core" | "plugin" | "theme" | "language"; slug: string; name: string; currentVersion: string; newVersion: string; status: string }
export interface MaintenanceStep { key: string; label: string; status: StepStatus; detail?: string }
export interface MaintenanceRun { id: string; siteId: string; siteName?: string; startedAt: string; finishedAt?: string; status: StepStatus; durationMs?: number; backupPath?: string; steps: MaintenanceStep[]; beforeVersions?: string; afterVersions?: string }
export interface AppSettings { scanConcurrency: number }
export interface AuthStatus { configured: boolean; authenticated: boolean; idleTimeoutMinutes: number; retryAfterSeconds: number }
export interface LoginResult { sessionToken: string; idleTimeoutMinutes: number }
export interface PasswordChangeInput { currentPassword: string; newPassword: string }
export interface AuditEvent { id: string; siteId?: string; actionType: string; target: string; status: "success" | "failed"; details?: string; createdAt: string }

export interface WpCliParameterDoc { parameter: string; description: string }
export interface WpCliCommandNode { command: string; fullCommand: string; description: string; url?: string; parameters: WpCliParameterDoc[]; subcommands: WpCliCommandNode[] }
export interface WpCliCatalog {
  available: boolean;
  source?: string;
  scrapedAt?: string;
  rootCommandCount: number;
  totalCommandCount: number;
  globalParameterCount: number;
  globalParameters: WpCliParameterDoc[];
  commands: WpCliCommandNode[];
  error?: string;
  technicalDetails?: string;
}
export interface ParsedWpCliParameter {
  rawSyntax: string;
  displayText: string;
  insertText: string;
  required: boolean;
  optional: boolean;
  repeatable: boolean;
  takesValue: boolean;
  valueOptional: boolean;
  placeholder?: string;
  positional: boolean;
  description: string;
}
export type WpCliSuggestionType = "command" | "subcommand" | "parameter" | "globalParameter" | "positional";
export interface WpCliSuggestion {
  id: string;
  type: WpCliSuggestionType;
  label: string;
  description: string;
  insertText: string;
  replaceStart: number;
  replaceEnd: number;
  command?: WpCliCommandNode;
  parameter?: ParsedWpCliParameter;
}
export type WpCliRisk = "readOnly" | "mutating" | "highRisk";
export interface WpCliCommandInspection {
  risk: WpCliRisk;
  commandFamily: string;
  summary: string;
  requiresConfirmation: boolean;
  requiresTypedConfirmation: boolean;
  confirmationPhrase?: string;
}
export type WpCliExecutionStatus = "success" | "warning" | "failed";
export interface WpCliExecutionResult {
  status: WpCliExecutionStatus;
  risk: WpCliRisk;
  commandFamily: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  startedAt: string;
  finishedAt: string;
  truncated: boolean;
}
