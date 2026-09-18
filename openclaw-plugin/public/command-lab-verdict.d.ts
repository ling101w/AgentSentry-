export type CommandLabRecord = {
  id?: string;
  run_id?: string;
  session_key?: string;
  type?: string;
  title?: string;
  summary?: string;
  payload?: Record<string, any>;
};

export type CommandLabVerdictOptions = {
  fallbackScenario?: string;
  targetValue?: string;
  scenarioDefaults?: Record<string, { label?: string; tool?: string }>;
};

export const ALL_SESSIONS: "__all__";
export function canonicalSessionKey(value: unknown): string;
export function sessionKeysMatch(left: unknown, right: unknown): boolean;
export function isCommandLabLlmRecord(record: CommandLabRecord): boolean;
export function isOpenClawLlmPingRecord(record: CommandLabRecord): boolean;
export function isOpenClawLlmOfficeRecord(record: CommandLabRecord): boolean;
export function isFoundationNoiseRecord(record: CommandLabRecord): boolean;
export function collapseFoundationFindings(records: CommandLabRecord[]): CommandLabRecord[];
export function inferLabScenario(records: CommandLabRecord[], fallback?: string): string;
export function summarizeLabVerdict(records: CommandLabRecord[], options?: CommandLabVerdictOptions): Record<string, unknown>;
