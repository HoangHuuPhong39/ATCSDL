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
