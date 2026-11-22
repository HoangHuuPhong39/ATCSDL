import { useState, useEffect, useRef, useCallback } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import {
  AlertItem,
  AuditLogRow,
  AuthStatus,
  DashboardApiResponse,
  DataSourceMode,
  DbUser,
  DefenseHealth,
  Employee,
  FailedLogon,
  FgaEvent,
  TriggerAlert,
  getAuditKey,
  getFgaKey,
} from '../types/ids';
import {
  INITIAL_ALERTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_EMPLOYEES,
  INITIAL_FGA_EVENTS,
  INITIAL_TRIGGERS,
  INITIAL_USERS,
} from '../data/initialData';
import { evaluateOracleSqlBatch } from '../utils/oracleDetector';
import { maskUsername } from '../utils/privacy';

export type ToastType = 'success' | 'error' | 'info';

export const MAX_TRACKED_KEYS = 500;

export function formatUtcTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace('T', ' ').substring(0, 19);
}

/**
 * Adds a key to a Set while keeping total entries bounded to maxSize (FIFO eviction).
 */
export function addCappedToSet<T>(
  set: Set<T>,
  value: T,
  maxSize: number = MAX_TRACKED_KEYS
): void {
  if (set.has(value)) {
    set.delete(value);
  }
  set.add(value);
  while (set.size > maxSize) {
    const first = set.values().next();
    if (first.done) break;
    set.delete(first.value);
  }
}

export interface UseIdsTelemetryOptions {
  privacyMode: boolean;
  addToast: (message: string, type?: ToastType) => void;
}

export interface UseIdsTelemetryResult {
  authChecked: boolean;
  authenticated: boolean;
  csrfToken: string | null;
  authError: string | null;
  isLoggingIn: boolean;
  login: (token: string) => Promise<boolean>;
  logout: () => Promise<void>;

  users: DbUser[];
  setUsers: Dispatch<SetStateAction<DbUser[]>>;
  alerts: AlertItem[];
  setAlerts: Dispatch<SetStateAction<AlertItem[]>>;
  fgaEvents: FgaEvent[];
  setFgaEvents: Dispatch<SetStateAction<FgaEvent[]>>;
  triggers: TriggerAlert[];
  setTriggers: Dispatch<SetStateAction<TriggerAlert[]>>;
  auditLogs: AuditLogRow[];
  setAuditLogs: Dispatch<SetStateAction<AuditLogRow[]>>;
  employees: Employee[];
  failedLogons: FailedLogon[];
  defenseHealth: DefenseHealth | undefined;

  autoResponse: boolean;
  setAutoResponse: Dispatch<SetStateAction<boolean>>;
  autoRefresh: boolean;
  setAutoRefresh: Dispatch<SetStateAction<boolean>>;
  isRefreshing: boolean;
  isBridgeConnected: boolean;
  setIsBridgeConnected: Dispatch<SetStateAction<boolean>>;
  lastSyncTime: string | null;
  dsn: string;
  dataSource: DataSourceMode;
  activeMode: DataSourceMode;

  privacyModeRef: MutableRefObject<boolean>;
  reviewedKeysRef: MutableRefObject<Set<string>>;
  auditCutoffRef: MutableRefObject<string | null>;
  reviewedAuditKeysRef: MutableRefObject<Set<string>>;
  reviewedFgaKeysRef: MutableRefObject<Set<string>>;
  dismissedFgaKeysRef: MutableRefObject<Set<string>>;
  fgaCutoffRef: MutableRefObject<string | null>;
  reviewedTriggerIdsRef: MutableRefObject<Set<number>>;
  dismissedTriggerIdsRef: MutableRefObject<Set<number>>;
  simUserClearedAtRef: MutableRefObject<Record<string, string>>;

  handleUnauthorized: (message?: string) => void;
  markSimUserCleared: (username: string, timestamp?: string) => void;
  clearSimUserClearedState: () => void;
  syncFromOracleBackend: (notifyManual?: boolean) => Promise<boolean>;
  handleRefresh: (flush?: boolean) => Promise<void>;
  handleExecuteOracleSql: (sql: string, dbUser: string) => Promise<string[]>;
  handleSwitchMode: (mode: 'oracle_live' | 'simulation') => Promise<void>;
  postAuthenticatedJson: (url: string, body: unknown) => Promise<Response | null>;
  runWithMutationLock: <T>(fn: () => Promise<T>) => Promise<T>;
}

export function useIdsTelemetry({
  privacyMode,
  addToast,
}: UseIdsTelemetryOptions): UseIdsTelemetryResult {
  // Auth state
  const [authChecked, setAuthChecked] = useState<boolean>(false);
  const [authenticated, setAuthenticated] = useState<boolean>(false);
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);

  // Telemetry state
  const [users, setUsers] = useState<DbUser[]>(INITIAL_USERS);
  const [alerts, setAlerts] = useState<AlertItem[]>(INITIAL_ALERTS);
  const [fgaEvents, setFgaEvents] = useState<FgaEvent[]>(INITIAL_FGA_EVENTS);
  const [triggers, setTriggers] = useState<TriggerAlert[]>(INITIAL_TRIGGERS);
  const [auditLogs, setAuditLogs] = useState<AuditLogRow[]>(INITIAL_AUDIT_LOGS);
  const [employees, setEmployees] = useState<Employee[]>(INITIAL_EMPLOYEES);
  const [failedLogons, setFailedLogons] = useState<FailedLogon[]>([]);
  const [defenseHealth, setDefenseHealth] = useState<DefenseHealth | undefined>(undefined);

  // Control & connection state
  const [autoResponse, setAutoResponse] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isBridgeConnected, setIsBridgeConnected] = useState<boolean>(false);
  const [lastSyncTime, setLastSyncTime] = useState<string | null>(null);
  const [dsn, setDsn] = useState<string>('localhost:1521/FREEPDB1');
  const [dataSource, setDataSource] = useState<DataSourceMode>('disconnected');
  const [activeMode, setActiveMode] = useState<DataSourceMode>('simulation');

  // Refs for stable closures, mutation lock, and bounded key tracking
  const privacyModeRef = useRef<boolean>(privacyMode);
  privacyModeRef.current = privacyMode;

  const authenticatedRef = useRef<boolean>(authenticated);
  authenticatedRef.current = authenticated;

  const csrfTokenRef = useRef<string | null>(csrfToken);
  csrfTokenRef.current = csrfToken;

  const pendingMutationsRef = useRef<number>(0);
  const mutationEpochRef = useRef<number>(0);

  const knownAlertKeysRef = useRef<Set<string>>(
    new Set(INITIAL_ALERTS.slice(0, MAX_TRACKED_KEYS).map((a) => a.key))
  );
  const reviewedKeysRef = useRef<Set<string>>(new Set());
  const auditCutoffRef = useRef<string | null>(null);
  const reviewedAuditKeysRef = useRef<Set<string>>(new Set());
  const reviewedFgaKeysRef = useRef<Set<string>>(new Set());
  const dismissedFgaKeysRef = useRef<Set<string>>(new Set());
  const fgaCutoffRef = useRef<string | null>(null);
  const reviewedTriggerIdsRef = useRef<Set<number>>(new Set());
  const dismissedTriggerIdsRef = useRef<Set<number>>(new Set());
  const alertsRef = useRef<AlertItem[]>(alerts);
  alertsRef.current = alerts;
  const simUserClearedAtRef = useRef<Record<string, string>>({});
  const simPostClearAlertKeysRef = useRef<Set<string>>(new Set());

  const handleUnauthorized = useCallback((message?: string) => {
    authenticatedRef.current = false;
    csrfTokenRef.current = null;
    setAuthenticated(false);
    setCsrfToken(null);
    setIsBridgeConnected(false);
    setDataSource('disconnected');
    if (message) {
      setAuthError(message);
    }
  }, []);

  const markSimUserCleared = useCallback((username: string, timestamp?: string) => {
    const uname = username.trim().toUpperCase();
    if (!uname) return;
    const nowUtc = timestamp || formatUtcTimestamp();
    let maxUserAlertTime = '';
    for (const a of alertsRef.current) {
      if (a.user.toUpperCase() === uname) {
        if (a.time && a.time > maxUserAlertTime) {
          maxUserAlertTime = a.time;
        }
        simPostClearAlertKeysRef.current.delete(a.key);
      }
    }
    simUserClearedAtRef.current[uname] =
      maxUserAlertTime && maxUserAlertTime > nowUtc ? maxUserAlertTime : nowUtc;
  }, []);

  const clearSimUserClearedState = useCallback(() => {
    simUserClearedAtRef.current = {};
    simPostClearAlertKeysRef.current.clear();
  }, []);

  const beginMutation = useCallback(() => {
    pendingMutationsRef.current += 1;
    mutationEpochRef.current += 1;
  }, []);

  const endMutation = useCallback(() => {
    pendingMutationsRef.current = Math.max(0, pendingMutationsRef.current - 1);
    mutationEpochRef.current += 1;
  }, []);

  const runWithMutationLock = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      beginMutation();
      try {
        return await fn();
      } finally {
        endMutation();
      }
    },
    [beginMutation, endMutation]
  );

  const postAuthenticatedJson = useCallback(
    async (url: string, body: unknown): Promise<Response | null> => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (csrfTokenRef.current) {
        headers['X-CSRF-Token'] = csrfTokenRef.current;
      }
      try {
        const res = await fetch(url, {
          method: 'POST',
          credentials: 'include',
          headers,
          body: JSON.stringify(body),
        });
        if (res.status === 401) {
          handleUnauthorized('Phiên xác thực SOC đã hết hạn. Vui lòng đăng nhập lại.');
        }
        return res;
      } catch {
        return null;
      }
    },
    [handleUnauthorized]
  );

  // Check initial SOC auth session on mount
  useEffect(() => {
    let cancelled = false;
    const checkAuthStatus = async () => {
      try {
        const res = await fetch('/api/auth/status', { credentials: 'include' });
        if (!res.ok) {
          if (!cancelled) {
            handleUnauthorized();
            setAuthChecked(true);
          }
          return;
        }
        const data = (await res.json()) as AuthStatus;
        if (cancelled) return;
        const isAuthed = Boolean(data.authenticated);
        const token = data.csrfToken ?? null;
        authenticatedRef.current = isAuthed;
        csrfTokenRef.current = token;
        setAuthenticated(isAuthed);
        setCsrfToken(token);
        setAuthError(null);
        setAuthChecked(true);
      } catch {
        if (!cancelled) {
          handleUnauthorized();
          setAuthChecked(true);
        }
      }
    };
    void checkAuthStatus();
    return () => {
      cancelled = true;
    };
  }, [handleUnauthorized]);

  const login = useCallback(async (token: string): Promise<boolean> => {
    const trimmed = token.trim();
    if (!trimmed) {
      setAuthError('Vui lòng nhập mã xác thực SOC.');
      return false;
    }
    setIsLoggingIn(true);
    setAuthError(null);
    try {
      const res = await fetch('/api/auth/session', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: trimmed }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        ok?: boolean;
        csrfToken?: string;
        error?: string;
        message?: string;
      };
      if (!res.ok || data.ok === false) {
        setAuthError(
          data.error || data.message || 'Mã xác thực SOC không hợp lệ hoặc bị từ chối.'
        );
        return false;
      }
      const nextCsrf = data.csrfToken ?? null;
      csrfTokenRef.current = nextCsrf;
      authenticatedRef.current = true;
      setCsrfToken(nextCsrf);
      setAuthenticated(true);
      setAuthChecked(true);
      setAuthError(null);
      return true;
    } catch {
      setAuthError('Không thể kết nối máy chủ xác thực SOC.');
      return false;
    } finally {
      setIsLoggingIn(false);
    }
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (csrfTokenRef.current) {
      headers['X-CSRF-Token'] = csrfTokenRef.current;
    }
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({}),
      });
    } catch {
      // Clear local session state even if network fails
    } finally {
      handleUnauthorized();
      setAuthError(null);
      setLastSyncTime(null);
      auditCutoffRef.current = null;
      fgaCutoffRef.current = null;
      reviewedKeysRef.current.clear();
      reviewedAuditKeysRef.current.clear();
      reviewedFgaKeysRef.current.clear();
      dismissedFgaKeysRef.current.clear();
      reviewedTriggerIdsRef.current.clear();
      dismissedTriggerIdsRef.current.clear();
      simUserClearedAtRef.current = {};
      simPostClearAlertKeysRef.current.clear();
      knownAlertKeysRef.current = new Set(
        INITIAL_ALERTS.slice(0, MAX_TRACKED_KEYS).map((a) => a.key)
      );
    }
  }, [handleUnauthorized]);

  const syncFromOracleBackend = useCallback(
    async (notifyManual: boolean = false): Promise<boolean> => {
      if (!authenticatedRef.current) return false;
      if (!notifyManual && pendingMutationsRef.current > 0) return false;

      const startEpoch = mutationEpochRef.current;
      try {
        const res = await fetch(notifyManual ? '/api/data?flush=1' : '/api/data', {
          credentials: 'include',
        });
        if (res.status === 401) {
          handleUnauthorized('Phiên xác thực SOC đã hết hạn. Vui lòng đăng nhập lại.');
          return false;
        }
        if (!res.ok) {
          setIsBridgeConnected(false);
          setDataSource('disconnected');
          return false;
        }

        const data = (await res.json()) as DashboardApiResponse;
        if (
          pendingMutationsRef.current > 0 ||
          mutationEpochRef.current !== startEpoch
        ) {
          return false;
        }

        if (!data || !data.ok) {
          setIsBridgeConnected(false);
          setDataSource('disconnected');
          return false;
        }

        const bridgeConnected = Boolean(data.oracle_bridge_connected ?? false);
        setIsBridgeConnected(bridgeConnected);
        if (data.dsn) setDsn(data.dsn);
        if (data.data_source) {
          setDataSource(data.data_source);
        } else {
          setDataSource(bridgeConnected ? 'oracle_live' : 'simulation');
        }
        if (data.active_mode) {
          setActiveMode(data.active_mode);
        } else if (data.data_source && data.data_source !== 'disconnected') {
          setActiveMode(data.data_source);
        }
        if (typeof data.auto_response === 'boolean') {
          setAutoResponse(data.auto_response);
        }
        if (data.defense_health) setDefenseHealth(data.defense_health);
        if (Array.isArray(data.failed_logons)) setFailedLogons(data.failed_logons);

        if (Array.isArray(data.alerts)) {
          const incomingAlerts: AlertItem[] = data.alerts.map((a) => {
            const isReviewed = Boolean(a.reviewed || reviewedKeysRef.current.has(a.key));
            if (isReviewed) addCappedToSet(reviewedKeysRef.current, a.key);
            return { ...a, reviewed: isReviewed };
          });
          const brandNew = incomingAlerts.filter((a) => !knownAlertKeysRef.current.has(a.key));
          incomingAlerts.forEach((a) => addCappedToSet(knownAlertKeysRef.current, a.key));
          if (brandNew.length > 0 && !notifyManual) {
            const latest = brandNew[0];
            addToast(
              `[Oracle Live Alert] Phát hiện ${brandNew.length} cảnh báo mới từ ${maskUsername(
                latest.user,
                privacyModeRef.current
              )}: ${latest.attack_type}`,
              latest.severity === 'CRITICAL' ? 'error' : 'info'
            );
          }
          setAlerts(incomingAlerts);
        }

        if (Array.isArray(data.users)) setUsers(data.users);

        if (Array.isArray(data.fga_events)) {
          const incomingFga = data.fga_events
            .filter((f) => {
              const fk = getFgaKey(f);
              if (dismissedFgaKeysRef.current.has(fk)) return false;
              if (
                fgaCutoffRef.current &&
                f.EVENT_TIMESTAMP &&
                f.EVENT_TIMESTAMP <= fgaCutoffRef.current
              ) {
                return false;
              }
              return true;
            })
            .map((f) => {
              const fk = getFgaKey(f);
              const isReviewed = Boolean(f.reviewed || reviewedFgaKeysRef.current.has(fk));
              if (isReviewed) addCappedToSet(reviewedFgaKeysRef.current, fk);
              return { ...f, reviewed: isReviewed };
            });
          setFgaEvents(incomingFga);
        }

        if (Array.isArray(data.triggers)) {
          const incomingTriggers = data.triggers
            .filter((t) => !dismissedTriggerIdsRef.current.has(t.ALERT_ID))
            .map((t) => {
              const isReviewed = Boolean(t.reviewed || reviewedTriggerIdsRef.current.has(t.ALERT_ID));
              if (isReviewed) addCappedToSet(reviewedTriggerIdsRef.current, t.ALERT_ID);
              return { ...t, reviewed: isReviewed };
            });
          setTriggers(incomingTriggers);
        }

        if (Array.isArray(data.audit_logs)) {
          const incomingAudit = data.audit_logs
            .filter(
              (row) =>
                !auditCutoffRef.current ||
                !row.EVENT_TIMESTAMP ||
                row.EVENT_TIMESTAMP > auditCutoffRef.current
            )
            .map((row) => {
              const ak = getAuditKey(row);
              const isReviewed = Boolean(row.reviewed || reviewedAuditKeysRef.current.has(ak));
              if (isReviewed) addCappedToSet(reviewedAuditKeysRef.current, ak);
              return { ...row, reviewed: isReviewed };
            });
          setAuditLogs(incomingAudit);
        }

        if (Array.isArray(data.employees)) setEmployees(data.employees);
        setLastSyncTime(data.last_oracle_sync || formatUtcTimestamp());
        return true;
      } catch {
        setIsBridgeConnected(false);
        setDataSource('disconnected');
        return false;
      }
    },
    [addToast, handleUnauthorized]
  );

  // Initial sync once authenticated
  useEffect(() => {
    if (!authenticated) return;
    void syncFromOracleBackend(true);
  }, [authenticated, syncFromOracleBackend]);

  // 3s periodic polling while authenticated and autoRefresh is enabled
  useEffect(() => {
    if (!authenticated || !autoRefresh) return;
    const timer = setInterval(() => {
      void syncFromOracleBackend(false);
    }, 3000);
    return () => clearInterval(timer);
  }, [authenticated, autoRefresh, syncFromOracleBackend]);

  const handleRefresh = useCallback(
    async (flush: boolean = true) => {
      setIsRefreshing(true);
      try {
        const ok = await syncFromOracleBackend(flush);
        if (flush && ok) {
          addToast('Đã đồng bộ thời gian thực Unified Audit Trail & FGA từ Oracle 23ai!', 'success');
        } else if (flush && !ok && authenticatedRef.current) {
          addToast('Không thể đồng bộ dữ liệu từ máy chủ Oracle Bridge.', 'error');
        }
      } finally {
        setIsRefreshing(false);
      }
    },
    [syncFromOracleBackend, addToast]
  );

  const handleSwitchMode = useCallback(
    async (mode: 'oracle_live' | 'simulation') => {
      const res = await runWithMutationLock(() =>
        postAuthenticatedJson('/api/mode', { mode })
      );
      if (res && res.status === 401) return;
      if (!res || !res.ok) {
        addToast('Không thể chuyển chế độ nguồn dữ liệu trên máy chủ.', 'error');
        return;
      }
      setActiveMode(mode);
      await syncFromOracleBackend(true);
      addToast(
        mode === 'oracle_live'
          ? 'Đã chuyển sang chế độ Live Oracle 23ai!'
          : 'Đã chuyển sang chế độ Simulator!',
        'info'
      );
    },
    [runWithMutationLock, postAuthenticatedJson, syncFromOracleBackend, addToast]
  );

  const handleExecuteOracleSql = useCallback(
    async (sql: string, dbUser: string): Promise<string[]> => {
      const recentUserAudit = auditLogs.find((r) => r.DBUSERNAME === dbUser);
      const sessionHost = recentUserAudit?.USERHOST || 'LAPTOP-R03ORTGV';
      const sessionOsUser = recentUserAudit?.OS_USERNAME || 'pc';

      const res = await runWithMutationLock(() =>
        postAuthenticatedJson('/api/execute-oracle-sql', {
          sql,
          dbUser,
          host: sessionHost,
          osUser: sessionOsUser,
          client: 'SQL Developer',
        })
      );

      if (res !== null) {
        if (res.status === 401) {
          handleUnauthorized('Phiên xác thực SOC đã hết hạn. Vui lòng đăng nhập lại.');
          return [];
        }
        if (!res.ok) {
          const errBody = (await res.json().catch(() => ({}))) as {
            error?: unknown;
            message?: unknown;
          };
          const errMsg =
            (typeof errBody.error === 'string' && errBody.error.trim()) ||
            (typeof errBody.message === 'string' && errBody.message.trim()) ||
            res.statusText ||
            'Yêu cầu không hợp lệ';
          const formattedErr = `Lỗi từ máy chủ (${res.status}): ${errMsg}`;
          addToast(formattedErr, 'error');
          return [formattedErr];
        }

        const data = (await res.json().catch(() => ({}))) as {
          outputs?: unknown[];
          new_alerts_count?: number;
        };
        await syncFromOracleBackend(true);
        const count = Number(data.new_alerts_count || 0);
        const maskedUser = maskUsername(dbUser, privacyModeRef.current);
        if (count > 0) {
          addToast(
            `[Oracle SQL Developer -> SOC] Đã phát hiện ${count} cảnh báo xâm nhập từ phiên ${maskedUser}!`,
            'error'
          );
        } else {
          addToast(
            `[Oracle SQL Developer -> SOC] Đã ghi nhận câu lệnh hợp lệ từ ${maskedUser} vào Unified Audit Trail.`,
            'info'
          );
        }
        return Array.isArray(data.outputs) ? data.outputs.map(String) : [];
      }

      // Offline fallback evaluation ONLY when backend route is unreachable (network error -> res === null)
      const normalizedUser = dbUser.trim().toUpperCase() || 'U1';
      const userClearedCutoff = simUserClearedAtRef.current[normalizedUser];
      const activeAlertsForBatch = userClearedCutoff
        ? alerts.filter(
            (a) =>
              a.user.toUpperCase() !== normalizedUser ||
              (a.time && a.time > userClearedCutoff) ||
              simPostClearAlertKeysRef.current.has(a.key)
          )
        : alerts;

      const outcome = evaluateOracleSqlBatch(
        sql,
        dbUser,
        users,
        activeAlertsForBatch,
        triggers,
        autoResponse,
        sessionHost,
        sessionOsUser,
        'SQL Developer',
        employees,
        simUserClearedAtRef.current
      );

      outcome.newAlerts.forEach((a) => {
        addCappedToSet(knownAlertKeysRef.current, a.key);
        addCappedToSet(simPostClearAlertKeysRef.current, a.key);
      });
      setAlerts((prev) => [...outcome.newAlerts, ...prev]);
      setFgaEvents((prev) => [...outcome.newFgaEvents, ...prev]);
      setTriggers((prev) => [...outcome.newTriggers, ...prev]);
      setAuditLogs((prev) => [...outcome.newAuditLogs, ...prev]);
      setUsers(outcome.updatedUsers);
      setLastSyncTime(formatUtcTimestamp());

      const maskedUser = maskUsername(dbUser, privacyModeRef.current);
      if (outcome.newAlerts.length > 0) {
        addToast(
          `[Oracle SQL Developer -> SOC] Đã phát hiện ${outcome.newAlerts.length} cảnh báo xâm nhập từ phiên ${maskedUser}!`,
          'error'
        );
      }

      return outcome.oracleOutputs;
    },
    [
      auditLogs,
      runWithMutationLock,
      postAuthenticatedJson,
      handleUnauthorized,
      syncFromOracleBackend,
      addToast,
      users,
      alerts,
      triggers,
      autoResponse,
      employees,
    ]
  );

  return {
    authChecked,
    authenticated,
    csrfToken,
    authError,
    isLoggingIn,
    login,
    logout,

    users,
    setUsers,
    alerts,
    setAlerts,
    fgaEvents,
    setFgaEvents,
    triggers,
    setTriggers,
    auditLogs,
    setAuditLogs,
    employees,
    failedLogons,
    defenseHealth,

    autoResponse,
    setAutoResponse,
    autoRefresh,
    setAutoRefresh,
    isRefreshing,
    isBridgeConnected,
    setIsBridgeConnected,
    lastSyncTime,
    dsn,
    dataSource,
    activeMode,

    privacyModeRef,
    reviewedKeysRef,
    auditCutoffRef,
    reviewedAuditKeysRef,
    reviewedFgaKeysRef,
    dismissedFgaKeysRef,
    fgaCutoffRef,
    reviewedTriggerIdsRef,
    dismissedTriggerIdsRef,
    simUserClearedAtRef,

    handleUnauthorized,
    markSimUserCleared,
    clearSimUserClearedState,
    syncFromOracleBackend,
    handleRefresh,
    handleExecuteOracleSql,
    handleSwitchMode,
    postAuthenticatedJson,
    runWithMutationLock,
  };
}
