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
  vulnerabilitySummary?: SiteVulnerabilitySummary;
}

export interface SiteVulnerabilitySummary { criticalCount: number; highCount: number; mediumCount: number; lowCount: number; infoCount: number; unknownCount: number; lastCheckedAt: string; feedUpdatedAt?: string; inventoryObservedAt?: string; inventoryStale: boolean }

export type SnapshotSource = "scan" | "baseline" | "pre_maintenance" | "post_maintenance" | "manual";
export type SnapshotStatus = "complete" | "partial";
export type SnapshotSection = "core" | "plugins" | "themes" | "users" | "configuration" | "cron" | "files";
export type SnapshotSectionStatus = "complete" | "failed" | "not_collected";
export type SnapshotChangeType = "added" | "removed" | "updated" | "enabled" | "disabled" | "activated" | "deactivated" | "role_changed" | "version_changed" | "configuration_changed" | "scheduled" | "unscheduled" | "unknown";
export type SnapshotChangeSeverity = "info" | "attention" | "warning" | "critical";
export type SnapshotChangeOrigin = "scan" | "maintenance" | "manual" | "unknown";
export type SnapshotComparisonStatus = "compared" | "unavailable";
export type SnapshotValue = { type: "string"; value: string } | { type: "boolean"; value: boolean } | { type: "number"; value: number } | { type: "null" };

export interface SnapshotCompleteness { core: SnapshotSectionStatus; plugins: SnapshotSectionStatus; themes: SnapshotSectionStatus; users: SnapshotSectionStatus; configuration: SnapshotSectionStatus; cron: SnapshotSectionStatus; files: SnapshotSectionStatus }
export interface SnapshotMetadata { snapshotId: string; siteId: string; createdAt: string; scanRunId: string | null; maintenanceRunId: string | null; source: SnapshotSource; schemaVersion: number; status: SnapshotStatus; wordpressRootIdentity: string | null; scanTimestamp: string; appVersion: string | null; isBaseline: boolean; previousSnapshotId: string | null }
export interface SnapshotCore { version: string; locale: string | null; multisite: boolean | null; phpVersion: string | null }
export interface SnapshotPlugin { slug: string; name: string; version: string; status: string; autoUpdate: boolean | null; updateAvailable: boolean; availableVersion: string | null }
export interface SnapshotTheme extends SnapshotPlugin { active: boolean }
export interface SnapshotUser { id: number; login: string; displayName: string | null; email: string; roles: string[]; registeredAt: string | null }
export interface SnapshotConfiguration { key: string; value: SnapshotValue }
export interface SnapshotCronEvent { identity: string; hook: string; schedule: string | null; recurrence: string | null; argsFingerprint: string | null; nextRunAt: string | null }
export interface SnapshotFileState { relativePath: string; category: string; fileType: string; sizeBytes: number | null; modifiedAt: string | null; sha256: string | null }
export interface SiteSnapshot { metadata: SnapshotMetadata; completeness: SnapshotCompleteness; core: SnapshotCore | null; plugins: SnapshotPlugin[]; themes: SnapshotTheme[]; users: SnapshotUser[]; configuration: SnapshotConfiguration[]; cron: SnapshotCronEvent[]; files: SnapshotFileState[] }
export interface SnapshotChange { id: string; siteId: string; fromSnapshotId: string; toSnapshotId: string; category: SnapshotSection; entityType: string; entityKey: string; changeType: SnapshotChangeType; field: string | null; oldValue: SnapshotValue | null; newValue: SnapshotValue | null; severity: SnapshotChangeSeverity; summary: string; metadata: Record<string, SnapshotValue>; origin: SnapshotChangeOrigin; seen: boolean; createdAt: string }
export interface SnapshotDiffSection { category: SnapshotSection; status: SnapshotComparisonStatus; reason: string | null }
export interface SnapshotDiff { id: string; siteId: string; fromSnapshotId: string; toSnapshotId: string; createdAt: string; schemaVersion: number; origin: SnapshotChangeOrigin; maintenanceRunId: string | null; sections: SnapshotDiffSection[]; changes: SnapshotChange[] }
export interface SiteChangeHistory { latestSnapshot: SnapshotMetadata | null; baselineSnapshot: SnapshotMetadata | null; comparison: SnapshotDiff | null }
export interface SiteChangeSummary { siteId: string; latestSnapshotAt: string | null; latestChangeCount: number; unseenChangeCount: number; importantChangeSummary: string | null }
export interface SnapshotHistoryItem { snapshot: SnapshotMetadata; changeCount: number; importantChangeSummary: string | null }

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
export type ErrorCategory = "network" | "dns" | "connection_timeout" | "ssh_authentication" | "ssh_host_key" | "ssh_channel" | "ssh_command" | "wp_cli" | "database" | "http" | "filesystem" | "backup" | "update" | "parse" | "authentication" | "application" | "wordfence_api" | "vulnerability_feed" | "vulnerability_parse" | "vulnerability_match" | "snapshot_build" | "snapshot_persist" | "snapshot_diff" | "snapshot_schema" | "unknown";
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
export type FindingSeverity = "info" | "attention" | "warning" | "critical" | "problem";
export type FindingDisposition = "active" | "ignored" | "trusted" | "expired_exception" | "trusted_changed" | "trusted_missing";
export interface AffectedVersionRange { label: string; fromVersion: string; fromInclusive: boolean; toVersion: string; toInclusive: boolean }
export interface VulnerabilityCandidate { provider: string; vulnerabilityId: string; title: string; description?: string; informational: boolean; cve?: string; cveLink?: string; published?: string; updated?: string; cvssVector?: string; cvssScore?: number; cvssRating?: string; cweId?: number; cweName?: string; cweDescription?: string; researchers: string[]; references: string[]; copyrights?: unknown; softwareType: "core" | "plugin" | "theme"; softwareSlug: string; softwareName: string; affectedRanges: AffectedVersionRange[]; patched: boolean; patchedVersions: string[]; remediation?: string }
export interface VulnerabilityMatch extends VulnerabilityCandidate { installedVersion: string; installedStatus: string; updateVersion?: string; matchedRanges: string[] }
export interface Finding { id?: string; category: string; severity: FindingSeverity; title: string; detail: string; path?: string; checksumStatus?: ChecksumStatus; observedAt?: string; disposition?: FindingDisposition; exceptionId?: string; trustedFileId?: string; policyReason?: string; policyTarget?: string; vulnerability?: VulnerabilityMatch }
export interface FindingException { id: string; siteId: string; siteName: string; checkType: string; findingType: string; target: string; scope: "site"; reason: string; note?: string; createdAt: string; expiresAt?: string; active: boolean }
export interface FindingExceptionInput { siteId: string; findingId: string; expiresAt?: string; note?: string }
export type TrustedFileStatus = "trusted" | "changed" | "missing" | "unchecked";
export interface TrustedFile { id: string; siteId: string; siteName: string; relativePath: string; trustedSha256: string; currentSha256?: string; sizeBytes: number; currentSizeBytes?: number; modifiedAtSnapshot?: string; currentModifiedAt?: string; fileType: string; status: TrustedFileStatus; trustedAt: string; lastCheckedAt?: string; note?: string; active: boolean }
export interface TrustedFileInput { siteId: string; findingId: string; note?: string }
export interface SecurityPolicyMutationResult { scan?: ScanResult; findingException?: FindingException; trustedFile?: TrustedFile }
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
export interface WordfenceIntegrationStatus { configured: boolean; connectionStatus: "not_tested" | "connected" | "failed"; feedStatus: "missing" | "current" | "stale" | "refreshing" | "failed"; lastSuccessfulUpdateAt?: string; nextAutomaticUpdateAt?: string; vulnerabilityCount: number; softwareRecordCount: number; refreshRunning: boolean; refreshPhase?: string; cooldownRemainingSeconds: number; lastError?: string }
export interface VulnerabilityRefreshJobState { id: string; status: "queued" | "running" | "completed" | "failed"; phase?: "download" | "validate" | "process" | "database" | "complete"; createdAt: string; startedAt?: string; finishedAt?: string; downloadedBytes: number; vulnerabilityCount: number; softwareRecordCount: number; automatic: boolean; error?: TechnicalError }
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
