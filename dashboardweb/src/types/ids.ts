export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface AlertItem {
  key: string;
  severity: Severity;
  risk_score: number;
  response_level: number;
  response_label: string;
  time: string;
  user: string;
  attack_type: string;
  details: string;
  client_program: string;
  userhost: string;
  os_username: string;
  fga_policy?: string;
  audit_type?: string;
  context: string;
  reviewed?: boolean;
}

export interface FgaEvent {
  EVENT_TIMESTAMP: string;
  DBUSERNAME: string;
  ACTION_NAME: string;
  OBJECT_SCHEMA: string;
  OBJECT_NAME: string;
  FGA_POLICY_NAME: string;
  AUDIT_TYPE: string;
  SQL_TEXT: string;
  OS_USERNAME: string;
  USERHOST: string;
  CLIENT_PROGRAM_NAME: string;
  RETURN_CODE: number | string;
  reviewed?: boolean;
}

export interface TriggerAlert {
  ALERT_ID: number;
  EVENT_TIME: string;
  DB_USER: string;
  ATTACK_TYPE: string;
  DETAILS: string;
  reviewed?: boolean;
}

export interface AuditLogRow {
  EVENT_TIMESTAMP: string;
  DBUSERNAME: string;
  ACTION_NAME: string;
  OBJECT_SCHEMA: string;
  OBJECT_NAME: string;
  SQL_TEXT: string;
  RETURN_CODE: number;
  OS_USERNAME: string;
  USERHOST: string;
  CLIENT_PROGRAM_NAME: string;
  AUDIT_TYPE: string;
  FGA_POLICY_NAME?: string;
  UNIFIED_AUDIT_POLICIES?: string;
  reviewed?: boolean;
}

export interface DbUser {
  USERNAME: string;
  ACCOUNT_STATUS: 'OPEN' | 'LOCKED' | 'EXPIRED & LOCKED';
  DML_STATUS: 'FULL DML' | 'READ-ONLY';
  PRIVILEGES: string;
  RISK_SCORE: number;
  RESPONSE_LEVEL: number;
  RESPONSE_LABEL: string;
  LOCK_DATE?: string;
}

export interface Employee {
  MANV: string;
  CHUCVU?: string;
  HOTEN: string;
  LUONG: number;
  GIOITINH: string;
  CMND: string;
}

export interface FailedLogon {
  DBUSERNAME: string;
  FAIL_COUNT: number;
  LAST_ATTEMPT: string;
  OS_USERNAME: string;
  USERHOST: string;
  CLIENT_PROGRAM_NAME: string;
}

export interface Metrics {
  audit_count: number;
  alert_count: number;
  trigger_count: number;
  fga_count: number;
  locked_count: number;
  readonly_count: number;
  max_risk: number;
}

export type ActiveTab = 
  | 'home' 
  | 'alerts' 
  | 'fga' 
  | 'triggers' 
  | 'audit' 
  | 'users' 
  | 'ips' 
  | 'docs';

export type DataSourceMode = 'oracle_live' | 'simulation' | 'disconnected';

export interface DefenseHealth {
  trigger_ok: boolean;
  fga_ok: boolean;
  audit_ok: boolean;
  crypto_policy_ok: boolean;
  errors: string[];
}

export interface CommandAck {
  command_id: string;
  ok: boolean;
  message?: string;
}

export interface AuthStatus {
  authenticated: boolean;
  csrfToken?: string;
}

export interface DashboardApiResponse {
  ok: boolean;
  timestamp: string;
  dsn: string;
  oracle_bridge_connected: boolean;
  last_oracle_sync: string | null;
  data_source: DataSourceMode;
  active_mode: DataSourceMode;
  auto_response: boolean;
  defense_health?: DefenseHealth;
  metrics: Metrics;
  users: DbUser[];
  alerts: AlertItem[];
  fga_events: FgaEvent[];
  triggers: TriggerAlert[];
  audit_logs: AuditLogRow[];
  failed_logons?: FailedLogon[];
  employees: Employee[];
  error?: string;
}

export function getFgaKey(
  f: Pick<FgaEvent, 'EVENT_TIMESTAMP' | 'DBUSERNAME' | 'FGA_POLICY_NAME' | 'SQL_TEXT'>
): string {
  return `${f.EVENT_TIMESTAMP}_${f.DBUSERNAME}_${f.FGA_POLICY_NAME}_${f.SQL_TEXT || ''}`;
}

export function getAuditKey(
  r: Pick<AuditLogRow, 'EVENT_TIMESTAMP' | 'DBUSERNAME' | 'ACTION_NAME' | 'SQL_TEXT'>
): string {
  return `${r.EVENT_TIMESTAMP}_${r.DBUSERNAME}_${r.ACTION_NAME}_${(r.SQL_TEXT || '').slice(0, 40)}`;
}
