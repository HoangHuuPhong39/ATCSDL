/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Sidebar } from './components/Sidebar';
import { Header, LayoutWidthMode, UiDensityMode } from './components/Header';
import { OverviewTab } from './components/tabs/OverviewTab';
import { AlertsTab } from './components/tabs/AlertsTab';
import { FgaTab } from './components/tabs/FgaTab';
import { TriggersTab } from './components/tabs/TriggersTab';
import { AuditTab } from './components/tabs/AuditTab';
import { UsersTab } from './components/tabs/UsersTab';
import { IpsTab } from './components/tabs/IpsTab';
import { DocsTab } from './components/tabs/DocsTab';
import { AuditModal } from './components/AuditModal';
import { OracleBridgeModal } from './components/OracleBridgeModal';
import { PdfExportModal } from './components/PdfExportModal';
import { Toast, ToastMessage } from './components/Toast';
import { calculateSystemMetrics, recalculateUsersAfterReset } from './utils/analytics';
import { evaluateOracleSqlBatch } from './utils/oracleDetector';
import { PdfExportScope } from './utils/pdfExporter';
import {
  maskUsername,
  maskOsUser,
  maskHost,
  maskContextString,
  sanitizeSqlCredentials,
} from './utils/privacy';

import {
  AlertItem,
  AuditLogRow,
  DbUser,
  Employee,
  FgaEvent,
  Metrics,
  TriggerAlert,
  ActiveTab,
} from './types/ids';

import {
  INITIAL_ALERTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_EMPLOYEES,
  INITIAL_FGA_EVENTS,
  INITIAL_TRIGGERS,
  INITIAL_USERS,
} from './data/initialData';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('home');
  const [users, setUsers] = useState<DbUser[]>(INITIAL_USERS);
  const [alerts, setAlerts] = useState<AlertItem[]>(INITIAL_ALERTS);
  const [fgaEvents, setFgaEvents] = useState<FgaEvent[]>(INITIAL_FGA_EVENTS);
  const [triggers, setTriggers] = useState<TriggerAlert[]>(INITIAL_TRIGGERS);
  const [auditLogs, setAuditLogs] = useState<AuditLogRow[]>(INITIAL_AUDIT_LOGS);
  const [employees, setEmployees] = useState<Employee[]>(INITIAL_EMPLOYEES);

  const [autoResponse, setAutoResponse] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  // Privacy / Credential Masking Mode (default ON to keep usernames, hosts, OS users & CMND confidential)
  const [privacyMode, setPrivacyMode] = useState<boolean>(true);

  // Oracle SQL Developer Live Sync Modal & Status
  const [oracleBridgeOpen, setOracleBridgeOpen] = useState<boolean>(false);
  const [isBridgeConnected, setIsBridgeConnected] = useState<boolean>(true);
  const [lastSyncTime, setLastSyncTime] = useState<string | null>(
    new Date().toISOString().replace('T', ' ').substring(0, 19)
  );
  const knownAlertKeysRef = useRef<Set<string>>(new Set(INITIAL_ALERTS.map((a) => a.key)));
  const reviewedKeysRef = useRef<Set<string>>(new Set());
  const auditCutoffRef = useRef<string | null>(null);
  const reviewedAuditKeysRef = useRef<Set<string>>(new Set());

  // PDF Security Report Export Modal state
  const [pdfExportOpen, setPdfExportOpen] = useState<boolean>(false);
  const [pdfExportScope, setPdfExportScope] = useState<PdfExportScope>('full');

  const handleOpenPdfModal = (scope?: PdfExportScope) => {
    if (scope) {
      setPdfExportScope(scope);
    } else if (activeTab === 'alerts') {
      setPdfExportScope('alerts');
    } else if (activeTab === 'audit') {
      setPdfExportScope('audit');
    } else {
      setPdfExportScope('full');
    }
    setPdfExportOpen(true);
  };

  // Responsive Sidebar & Layout Customizer states
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);
  const [layoutWidth, setLayoutWidth] = useState<LayoutWidthMode>('boxed');
  const [uiDensity, setUiDensity] = useState<UiDensityMode>('comfortable');

  // Modal inspection states
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [selectedAlertKey, setSelectedAlertKey] = useState<string | null>(null);
  const [selectedAuditRowIndex, setSelectedAuditRowIndex] = useState<number | null>(null);

  // Toasts
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = useCallback((message: string, type: 'success' | 'error' | 'info' = 'success') => {
    const id = Date.now().toString() + Math.random().toString();
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  // Apply privacy masking to data structures when privacyMode is enabled
  const displayAlerts = useMemo<AlertItem[]>(() => {
    if (!privacyMode) return alerts;
    return alerts.map((a) => ({
      ...a,
      user: maskUsername(a.user, true),
      os_username: maskOsUser(a.os_username, true),
      userhost: maskHost(a.userhost, true),
      context: maskContextString(a.context, true),
      details: sanitizeSqlCredentials(a.details),
    }));
  }, [alerts, privacyMode]);

  const displayFgaEvents = useMemo<FgaEvent[]>(() => {
    if (!privacyMode) return fgaEvents;
    return fgaEvents.map((f) => ({
      ...f,
      DBUSERNAME: maskUsername(f.DBUSERNAME, true),
      OS_USERNAME: maskOsUser(f.OS_USERNAME, true),
      USERHOST: maskHost(f.USERHOST, true),
      SQL_TEXT: sanitizeSqlCredentials(f.SQL_TEXT),
    }));
  }, [fgaEvents, privacyMode]);

  const displayTriggers = useMemo<TriggerAlert[]>(() => {
    if (!privacyMode) return triggers;
    return triggers.map((t) => ({
      ...t,
      DB_USER: maskUsername(t.DB_USER, true),
      DETAILS: sanitizeSqlCredentials(t.DETAILS),
    }));
  }, [triggers, privacyMode]);

  const displayAuditLogs = useMemo<AuditLogRow[]>(() => {
    if (!privacyMode) return auditLogs;
    return auditLogs.map((r) => ({
      ...r,
      DBUSERNAME: maskUsername(r.DBUSERNAME, true),
      OS_USERNAME: maskOsUser(r.OS_USERNAME, true),
      USERHOST: maskHost(r.USERHOST, true),
      SQL_TEXT: sanitizeSqlCredentials(r.SQL_TEXT),
    }));
  }, [auditLogs, privacyMode]);

  // Resolve live selectedAlert & selectedAuditRow from display arrays so privacyMode applies inside modal too
  const selectedAlert = useMemo(
    () => (selectedAlertKey ? displayAlerts.find((a) => a.key === selectedAlertKey) || null : null),
    [displayAlerts, selectedAlertKey]
  );

  const selectedAuditRow = useMemo(
    () => (selectedAuditRowIndex !== null ? displayAuditLogs[selectedAuditRowIndex] || null : null),
    [displayAuditLogs, selectedAuditRowIndex]
  );

  // Metrics calculation
  const metrics: Metrics = useMemo(
    () =>
      calculateSystemMetrics(
        auditLogs.length,
        alerts.length,
        triggers.length,
        fgaEvents.length,
        users
      ),
    [auditLogs.length, alerts.length, triggers.length, fgaEvents.length, users]
  );

  // Sync state from backend /api/data
  const syncFromOracleBackend = useCallback(
    async (notifyManual: boolean = false) => {
      try {
        const res = await fetch('/api/data');
        if (!res.ok) return;
        const data = await res.json();
        if (data && data.ok) {
          setIsBridgeConnected(true);
          if (Array.isArray(data.alerts)) {
            const incomingAlerts: AlertItem[] = data.alerts.map((a: AlertItem) => ({
              ...a,
              reviewed: a.reviewed || reviewedKeysRef.current.has(a.key),
            }));
            const brandNew = incomingAlerts.filter((a) => !knownAlertKeysRef.current.has(a.key));
            incomingAlerts.forEach((a) => knownAlertKeysRef.current.add(a.key));
            if (brandNew.length > 0 && !notifyManual) {
              const latest = brandNew[0];
              addToast(
                `[Oracle Live Alert] Phát hiện ${brandNew.length} cảnh báo mới từ ${maskUsername(
                  latest.user,
                  privacyMode
                )}: ${latest.attack_type}`,
                latest.severity === 'CRITICAL' ? 'error' : 'info'
              );
            }
            setAlerts(incomingAlerts);
          }
          if (Array.isArray(data.users)) setUsers(data.users);
          if (Array.isArray(data.fga_events)) setFgaEvents(data.fga_events);
          if (Array.isArray(data.triggers)) setTriggers(data.triggers);
          if (Array.isArray(data.audit_logs)) {
            const incomingAudit = data.audit_logs
              .filter(
                (row: AuditLogRow) =>
                  !auditCutoffRef.current ||
                  !row.EVENT_TIMESTAMP ||
                  row.EVENT_TIMESTAMP > auditCutoffRef.current
              )
              .map((row: AuditLogRow, idx: number) => {
                const key = `${row.EVENT_TIMESTAMP}_${row.DBUSERNAME}_${row.ACTION_NAME}_${row.SQL_TEXT || idx}`;
                return {
                  ...row,
                  reviewed: row.reviewed || reviewedAuditKeysRef.current.has(key),
                };
              });
            setAuditLogs(incomingAudit);
          }
          if (Array.isArray(data.employees)) setEmployees(data.employees);
          setLastSyncTime(
            data.last_oracle_sync || new Date().toISOString().replace('T', ' ').substring(0, 19)
          );
        }
      } catch {
        // Fallback silently if offline
      }
    },
    [addToast, privacyMode]
  );

  // Initial sync & 3s periodic polling for live Oracle SQL Developer events
  useEffect(() => {
    syncFromOracleBackend(true);
  }, [syncFromOracleBackend]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      syncFromOracleBackend(false);
    }, 3000);
    return () => clearInterval(timer);
  }, [autoRefresh, syncFromOracleBackend]);

  // Flush / refresh handler
  const handleRefresh = async (flush: boolean = true) => {
    setIsRefreshing(true);
    await syncFromOracleBackend(true);
    setTimeout(() => {
      setIsRefreshing(false);
      if (flush) {
        addToast('Đã đồng bộ thời gian thực Unified Audit Trail & FGA từ Oracle 23ai!', 'success');
      }
    }, 300);
  };

  // Execute SQL batch from Oracle SQL Developer Worksheet Live Sync
  const handleExecuteOracleSql = async (sql: string, dbUser: string): Promise<string[]> => {
    try {
      const res = await fetch('/api/execute-oracle-sql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sql,
          dbUser,
          host: 'LAPTOP-R03ORTGV',
          osUser: 'pc',
          client: 'SQL Developer',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        await syncFromOracleBackend(true);
        const count = Number(data.new_alerts_count || 0);
        const maskedUser = maskUsername(dbUser, privacyMode);
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
        return Array.isArray(data.outputs) ? data.outputs : [];
      }
    } catch {
      // Fallback client-side evaluation if backend route is unreachable
    }

    const outcome = evaluateOracleSqlBatch(
      sql,
      dbUser,
      users,
      alerts,
      triggers,
      autoResponse,
      'LAPTOP-R03ORTGV',
      'pc',
      'SQL Developer'
    );

    outcome.newAlerts.forEach((a) => knownAlertKeysRef.current.add(a.key));
    setAlerts((prev) => [...outcome.newAlerts, ...prev]);
    setFgaEvents((prev) => [...outcome.newFgaEvents, ...prev]);
    setTriggers((prev) => [...outcome.newTriggers, ...prev]);
    setAuditLogs((prev) => [...outcome.newAuditLogs, ...prev]);
    setUsers(outcome.updatedUsers);
    setLastSyncTime(new Date().toISOString().replace('T', ' ').substring(0, 19));

    const maskedUser = maskUsername(dbUser, privacyMode);
    if (outcome.newAlerts.length > 0) {
      addToast(
        `[Oracle SQL Developer -> SOC] Đã phát hiện ${outcome.newAlerts.length} cảnh báo xâm nhập từ phiên ${maskedUser}!`,
        'error'
      );
    }

    return outcome.oracleOutputs;
  };

  // User Actions (Lock, Unlock, Revoke DML, Grant DML)
  const handleUserAction = (username: string, action: 'lock' | 'unlock' | 'revoke_dml' | 'grant_dml') => {
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

    setUsers((prev) =>
      prev.map((u) => {
        if (u.USERNAME !== username) return u;

        if (action === 'lock') {
          return {
            ...u,
            ACCOUNT_STATUS: 'LOCKED',
            LOCK_DATE: nowStr,
            RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 3),
            RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
          };
        } else if (action === 'unlock') {
          return {
            ...u,
            ACCOUNT_STATUS: 'OPEN',
            RISK_SCORE: 0,
            RESPONSE_LEVEL: 0,
            RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
            LOCK_DATE: undefined,
          };
        } else if (action === 'revoke_dml') {
          return {
            ...u,
            DML_STATUS: 'READ-ONLY',
            PRIVILEGES: 'SELECT',
            RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 2),
            RESPONSE_LABEL: 'Level 2: HIGH (Privilege Containment)',
          };
        } else if (action === 'grant_dml') {
          return {
            ...u,
            DML_STATUS: 'FULL DML',
            PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
          };
        }
        return u;
      })
    );

    fetch('/api/user-action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, action }),
    }).catch(() => {});

    const displayUser = maskUsername(username, privacyMode);
    if (action === 'lock') {
      addToast(`[Level 3 - Full Isolation] Đã KHÓA tài khoản ${displayUser} và ngắt kết nối phiên!`, 'error');
    } else if (action === 'unlock') {
      addToast(`Đã MỞ KHÓA tài khoản ${displayUser} và đặt lại Risk Score = 0!`, 'success');
    } else if (action === 'revoke_dml') {
      addToast(`[Level 2 - Privilege Containment] Đã thu hồi quyền DML của ${displayUser} -> Chuyển về READ-ONLY!`, 'error');
    } else if (action === 'grant_dml') {
      addToast(`Đã KHÔI PHỤC đầy đủ quyền DML (SELECT, INSERT, UPDATE, DELETE) cho ${displayUser}!`, 'success');
    }
  };

  // --- SOC Review & Reset Handlers ---

  // 1. Alerts Review & Reset
  const handleToggleReviewAlert = (key: string) => {
    if (reviewedKeysRef.current.has(key)) {
      reviewedKeysRef.current.delete(key);
    } else {
      reviewedKeysRef.current.add(key);
    }
    setAlerts((prev) =>
      prev.map((a) => (a.key === key ? { ...a, reviewed: !a.reviewed } : a))
    );
  };

  const handleMarkAllAlertsReviewed = () => {
    alerts.forEach((a) => reviewedKeysRef.current.add(a.key));
    setAlerts((prev) => prev.map((a) => ({ ...a, reviewed: true })));
    addToast(`Đã đánh dấu kiểm duyệt tất cả ${alerts.length} cảnh báo IDS!`, 'success');
  };

  const handleResetReviewedAlerts = () => {
    const reviewedKeys = alerts.filter((a) => a.reviewed).map((a) => a.key);
    const remaining = alerts.filter((a) => !a.reviewed);
    const removedCount = alerts.length - remaining.length;
    setAlerts(remaining);
    setUsers((prevUsers) => recalculateUsersAfterReset(prevUsers, remaining));
    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'reviewed', reviewed_keys: reviewedKeys }),
    }).catch(() => {});
    addToast(
      `Đã Reset ${removedCount} cảnh báo đã kiểm duyệt và cập nhật lại điểm rủi ro User!`,
      'success'
    );
  };

  const handleDismissSingleAlert = (key: string) => {
    const remaining = alerts.filter((a) => a.key !== key);
    setAlerts(remaining);
    setUsers((prevUsers) => recalculateUsersAfterReset(prevUsers, remaining));
    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'single_ids', alert_key: key }),
    }).catch(() => {});
    addToast('Đã kiểm duyệt & Reset cảnh báo, đồng thời cập nhật lại Risk Score!', 'info');
  };

  // 2. FGA Events Review & Reset
  const handleToggleReviewFga = (index: number) => {
    setFgaEvents((prev) =>
      prev.map((item, idx) => (idx === index ? { ...item, reviewed: !item.reviewed } : item))
    );
  };

  const handleMarkAllFgaReviewed = () => {
    setFgaEvents((prev) => prev.map((item) => ({ ...item, reviewed: true })));
    addToast(`Đã đánh dấu kiểm duyệt tất cả ${fgaEvents.length} sự kiện FGA!`, 'success');
  };

  const handleResetReviewedFga = () => {
    const remaining = fgaEvents.filter((item) => !item.reviewed);
    const removedCount = fgaEvents.length - remaining.length;
    setFgaEvents(remaining);
    addToast(`Đã Reset ${removedCount} sự kiện FGA đã kiểm duyệt!`, 'success');
  };

  const handleClearSingleFga = (index: number) => {
    setFgaEvents((prev) => prev.filter((_, idx) => idx !== index));
    addToast('Đã kiểm duyệt & Reset sự kiện FGA!', 'info');
  };

  const handleClearAllFga = () => {
    setFgaEvents([]);
    addToast('Đã Reset toàn bộ danh sách sự kiện FGA!', 'success');
  };

  // 3. Trigger Alerts Review & Reset
  const handleToggleReviewTrigger = (alertId: number) => {
    setTriggers((prev) =>
      prev.map((t) => (t.ALERT_ID === alertId ? { ...t, reviewed: !t.reviewed } : t))
    );
  };

  const handleMarkAllTriggersReviewed = () => {
    setTriggers((prev) => prev.map((t) => ({ ...t, reviewed: true })));
    addToast(`Đã đánh dấu kiểm duyệt tất cả ${triggers.length} bản ghi Trigger!`, 'success');
  };

  const handleResetReviewedTriggers = () => {
    const remaining = triggers.filter((t) => !t.reviewed);
    const removedCount = triggers.length - remaining.length;
    setTriggers(remaining);
    addToast(`Đã Reset ${removedCount} bản ghi Trigger đã kiểm duyệt!`, 'success');
  };

  const handleClearSingleTrigger = (alertId: number) => {
    setTriggers((prev) => prev.filter((t) => t.ALERT_ID !== alertId));
    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'single_trigger', alert_id: alertId }),
    }).catch(() => {});
    addToast(`Đã kiểm duyệt & Reset bản ghi Trigger #${alertId}!`, 'info');
  };

  // 4. Unified Audit Trail Review & Reset
  const getAuditKey = (row: AuditLogRow, idx: number) =>
    `${row.EVENT_TIMESTAMP}_${row.DBUSERNAME}_${row.ACTION_NAME}_${row.SQL_TEXT || idx}`;

  const handleToggleReviewAudit = (index: number) => {
    setAuditLogs((prev) =>
      prev.map((row, idx) => {
        if (idx === index) {
          const next = !row.reviewed;
          const k = getAuditKey(row, idx);
          if (next) reviewedAuditKeysRef.current.add(k);
          else reviewedAuditKeysRef.current.delete(k);
          return { ...row, reviewed: next };
        }
        return row;
      })
    );
  };

  const handleMarkAllAuditReviewed = () => {
    auditLogs.forEach((r, idx) => reviewedAuditKeysRef.current.add(getAuditKey(r, idx)));
    setAuditLogs((prev) => prev.map((row) => ({ ...row, reviewed: true })));
    addToast(`Đã đánh dấu kiểm duyệt toàn bộ ${auditLogs.length} bản ghi Audit Log!`, 'success');
  };

  const handleResetReviewedAudit = () => {
    const remaining = auditLogs.filter((row) => !row.reviewed);
    const removedCount = auditLogs.length - remaining.length;
    setAuditLogs(remaining);

    // Lưu mốc thời gian Reset kiểm toán để các lần đồng bộ tiếp theo không nạp lại log cũ
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    auditCutoffRef.current = nowStr;

    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'audit', cutoff: nowStr }),
    }).catch(() => {});

    addToast(`Đã Reset ${removedCount} bản ghi Audit Log đã kiểm duyệt!`, 'success');
  };

  const handleClearSingleAudit = (index: number) => {
    const targetRow = auditLogs[index];
    if (targetRow) {
      reviewedAuditKeysRef.current.add(getAuditKey(targetRow, index));
    }
    setAuditLogs((prev) => prev.filter((_, idx) => idx !== index));
    addToast('Đã kiểm duyệt & Reset bản ghi Unified Audit Trail!', 'info');
  };

  const handleResetAuditRowFromModal = () => {
    if (selectedAuditRowIndex !== null) {
      const targetRow = auditLogs[selectedAuditRowIndex];
      if (targetRow) {
        reviewedAuditKeysRef.current.add(getAuditKey(targetRow, selectedAuditRowIndex));
      }
      setAuditLogs((prev) => prev.filter((_, idx) => idx !== selectedAuditRowIndex));
      addToast('Đã kiểm duyệt & Reset bản ghi Unified Audit Trail!', 'info');
    }
  };

  const handleClearAllAudit = () => {
    setAuditLogs([]);
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    auditCutoffRef.current = nowStr;

    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'audit', cutoff: nowStr }),
    }).catch(() => {});

    addToast('Đã Reset toàn bộ nhật ký Unified Audit Trail!', 'success');
  };

  // 5. Global Overview Review & Reset (Across Alerts, FGA, and Triggers)
  const handleMarkAllSystemReviewed = () => {
    alerts.forEach((a) => reviewedKeysRef.current.add(a.key));
    setAlerts((prev) => prev.map((a) => ({ ...a, reviewed: true })));
    setFgaEvents((prev) => prev.map((f) => ({ ...f, reviewed: true })));
    setTriggers((prev) => prev.map((t) => ({ ...t, reviewed: true })));
    setAuditLogs((prev) => prev.map((r) => ({ ...r, reviewed: true })));
    addToast('Đã đánh dấu ĐÃ KIỂM DUYỆT cho toàn bộ Cảnh báo, FGA, Trigger và Audit Log!', 'success');
  };

  const handleResetAllReviewedSystem = () => {
    const reviewedKeys = alerts.filter((a) => a.reviewed).map((a) => a.key);
    const remainingAlerts = alerts.filter((a) => !a.reviewed);
    const remainingFga = fgaEvents.filter((f) => !f.reviewed);
    const remainingTriggers = triggers.filter((t) => !t.reviewed);
    const remainingAudit = auditLogs.filter((r) => !r.reviewed);

    setAlerts(remainingAlerts);
    setFgaEvents(remainingFga);
    setTriggers(remainingTriggers);
    setAuditLogs(remainingAudit);
    setUsers((prevUsers) => recalculateUsersAfterReset(prevUsers, remainingAlerts));

    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    if (remainingAudit.length === 0) {
      auditCutoffRef.current = nowStr;
    }

    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(
        remainingAlerts.length === 0
          ? { target: 'all', cutoff: nowStr }
          : { target: 'reviewed', reviewed_keys: reviewedKeys, cutoff: nowStr }
      ),
    }).catch(() => {});

    addToast('Đã Reset toàn bộ sự kiện & cảnh báo đã kiểm duyệt, đồng thời cập nhật lại điểm rủi ro!', 'success');
  };

  // Clear Alerts (Ids / Triggers / All)
  const handleClearAlerts = (target: 'ids' | 'triggers' | 'all') => {
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    if (target === 'all') {
      auditCutoffRef.current = nowStr;
    }

    fetch('/api/clear-alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, cutoff: nowStr }),
    }).catch(() => {});

    if (target === 'ids') {
      setAlerts([]);
      setUsers((prevUsers) => recalculateUsersAfterReset(prevUsers, []));
      addToast('Đã Reset toàn bộ cảnh báo IDS và khôi phục trạng thái an toàn (Risk = 0) cho User!', 'success');
    } else if (target === 'triggers') {
      setTriggers([]);
      addToast('Đã Reset nhật ký vi phạm Trigger!', 'success');
    } else if (target === 'all') {
      setAlerts([]);
      setTriggers([]);
      setFgaEvents([]);
      setAuditLogs([]);
      setUsers((prevUsers) => recalculateUsersAfterReset(prevUsers, []));
      addToast(
        'Đã hoàn tất kiểm duyệt & Reset toàn bộ Cảnh báo IDS, Bẫy FGA, Trigger và sẵn sàng nhận cảnh báo mới từ Oracle SQL Developer!',
        'success'
      );
    }
  };

  const handleToggleAutoResponse = (enabled: boolean) => {
    setAutoResponse(enabled);
    fetch('/api/toggle-ips', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auto_response: enabled }),
    }).catch(() => {});
    addToast(
      enabled
        ? 'Đã BẬT chế độ Tự động Phản ứng Đa cấp (Graduated IPS Engine)!'
        : 'Đã TẮT chế độ Tự động Phản ứng (Chuyển sang Giám sát Thụ động).',
      'info'
    );
  };

  // Open modals
  const handleOpenAlertModal = (alert: AlertItem) => {
    setSelectedAlertKey(alert.key);
    setSelectedAuditRowIndex(null);
    setModalOpen(true);
  };

  const handleOpenAuditModal = (row: AuditLogRow) => {
    const idx = displayAuditLogs.indexOf(row);
    setSelectedAuditRowIndex(idx >= 0 ? idx : 0);
    setSelectedAlertKey(null);
    setModalOpen(true);
  };

  const containerMaxWidthClass =
    layoutWidth === 'fluid'
      ? 'max-w-none'
      : layoutWidth === 'compact'
      ? 'max-w-[1280px]'
      : 'max-w-[1600px]';

  return (
    <div
      className={`min-h-screen bg-[#090e17] text-slate-100 flex flex-col font-sans ${
        uiDensity === 'compact' ? 'density-compact' : ''
      }`}
    >
      {/* Collapsible & Responsive Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={(t) => setActiveTab(t)}
        metrics={metrics}
        autoResponse={autoResponse}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
        isMobileOpen={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
      />

      {/* Main Container */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-200 ease-out ${
          isSidebarCollapsed ? 'lg:ml-[74px]' : 'lg:ml-64'
        } ml-0`}
      >
        <Header
          activeTab={activeTab}
          onRefresh={() => handleRefresh(true)}
          isRefreshing={isRefreshing}
          onOpenOracleBridge={() => setOracleBridgeOpen(true)}
          onOpenPdfExport={() => handleOpenPdfModal()}
          isBridgeConnected={isBridgeConnected}
          privacyMode={privacyMode}
          onTogglePrivacyMode={() => {
            setPrivacyMode((prev) => {
              const next = !prev;
              addToast(
                next
                  ? 'Đã BẬT Bảo mật Định danh: Ẩn Username, Host, OS User, Mật khẩu và CMND!'
                  : 'Đã TẮT Bảo mật Định danh: Hiển thị đầy đủ Username phục vụ đối chiếu.',
                'info'
              );
              return next;
            });
          }}
          isSidebarCollapsed={isSidebarCollapsed}
          onToggleSidebarCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
          onOpenMobileMenu={() => setIsMobileMenuOpen(true)}
          layoutWidth={layoutWidth}
          onChangeLayoutWidth={setLayoutWidth}
          uiDensity={uiDensity}
          onChangeUiDensity={setUiDensity}
        />

        <main
          className={`${
            uiDensity === 'compact' ? 'p-3 sm:p-4' : 'p-4 sm:p-6'
          } pb-12 flex-1 w-full mx-auto transition-all duration-200 ${containerMaxWidthClass}`}
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
            >
              {activeTab === 'home' && (
                <OverviewTab
                  metrics={metrics}
                  alerts={displayAlerts}
                  users={users}
                  fgaEvents={displayFgaEvents}
                  triggers={displayTriggers}
                  privacyMode={privacyMode}
                  onOpenAlertModal={handleOpenAlertModal}
                  onNavigateTab={(tab) => setActiveTab(tab)}
                  onToggleReviewAlert={handleToggleReviewAlert}
                  onDismissAlert={handleDismissSingleAlert}
                  onMarkAllReviewed={handleMarkAllSystemReviewed}
                  onResetReviewedAll={handleResetAllReviewedSystem}
                  onResetAllAfterAudit={() => handleClearAlerts('all')}
                  onOpenOracleBridge={() => setOracleBridgeOpen(true)}
                  onOpenPdfExport={() => handleOpenPdfModal('full')}
                />
              )}

              {activeTab === 'alerts' && (
                <AlertsTab
                  alerts={displayAlerts}
                  onOpenAlertModal={handleOpenAlertModal}
                  onDismissAlert={handleDismissSingleAlert}
                  onToggleReviewAlert={handleToggleReviewAlert}
                  onMarkAllAlertsReviewed={handleMarkAllAlertsReviewed}
                  onResetReviewedAlerts={handleResetReviewedAlerts}
                  onClearAlerts={handleClearAlerts}
                  onOpenOracleBridge={() => setOracleBridgeOpen(true)}
                  onExportAlertsPdf={() => handleOpenPdfModal('alerts')}
                />
              )}

              {activeTab === 'fga' && (
                <FgaTab
                  fgaEvents={displayFgaEvents}
                  onToggleReviewFga={handleToggleReviewFga}
                  onMarkAllFgaReviewed={handleMarkAllFgaReviewed}
                  onResetReviewedFga={handleResetReviewedFga}
                  onClearSingleFga={handleClearSingleFga}
                  onClearAllFga={handleClearAllFga}
                  onOpenOracleBridge={() => setOracleBridgeOpen(true)}
                />
              )}

              {activeTab === 'triggers' && (
                <TriggersTab
                  triggers={displayTriggers}
                  onToggleReviewTrigger={handleToggleReviewTrigger}
                  onMarkAllTriggersReviewed={handleMarkAllTriggersReviewed}
                  onResetReviewedTriggers={handleResetReviewedTriggers}
                  onClearSingleTrigger={handleClearSingleTrigger}
                  onClearAllTriggers={() => handleClearAlerts('triggers')}
                  onOpenOracleBridge={() => setOracleBridgeOpen(true)}
                  onNavigateTab={(tab) => setActiveTab(tab)}
                />
              )}

              {activeTab === 'audit' && (
                <AuditTab
                  auditLogs={displayAuditLogs}
                  onOpenAuditModal={handleOpenAuditModal}
                  onToggleReviewAudit={handleToggleReviewAudit}
                  onMarkAllAuditReviewed={handleMarkAllAuditReviewed}
                  onResetReviewedAudit={handleResetReviewedAudit}
                  onClearSingleAudit={handleClearSingleAudit}
                  onClearAllAudit={handleClearAllAudit}
                  onOpenOracleBridge={() => setOracleBridgeOpen(true)}
                  onExportAuditPdf={() => handleOpenPdfModal('audit')}
                />
              )}

              {activeTab === 'users' && (
                <UsersTab
                  users={users}
                  employees={employees}
                  privacyMode={privacyMode}
                  onNavigateTab={(tab) => setActiveTab(tab)}
                />
              )}

              {activeTab === 'ips' && (
                <IpsTab
                  users={users}
                  privacyMode={privacyMode}
                  autoResponse={autoResponse}
                  onToggleAutoResponse={handleToggleAutoResponse}
                  autoRefresh={autoRefresh}
                  onToggleAutoRefresh={(val) => {
                    setAutoRefresh(val);
                    addToast(
                      val
                        ? 'Đã BẬT tự động đồng bộ thời gian thực từ Oracle (3s)!'
                        : 'Đã TẮT tự động đồng bộ định kỳ.',
                      'info'
                    );
                  }}
                  onClearAll={() => handleClearAlerts('all')}
                  onUserAction={handleUserAction}
                />
              )}

              {activeTab === 'docs' && <DocsTab />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      {/* Inspection Modal with Review & Reset buttons */}
      <AuditModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        alertItem={selectedAlert}
        auditRow={selectedAuditRow}
        onToggleReviewAlert={handleToggleReviewAlert}
        onResolveAndResetAlert={handleDismissSingleAlert}
        onResetAuditRow={handleResetAuditRowFromModal}
      />

      {/* Oracle SQL Developer Live Sync & Bridge Modal */}
      <OracleBridgeModal
        isOpen={oracleBridgeOpen}
        onClose={() => setOracleBridgeOpen(false)}
        users={users}
        isBridgeConnected={isBridgeConnected}
        lastSyncTime={lastSyncTime}
        privacyMode={privacyMode}
        onExecuteOracleSql={handleExecuteOracleSql}
      />

      {/* PDF Security Report Studio Modal */}
      <PdfExportModal
        isOpen={pdfExportOpen}
        onClose={() => setPdfExportOpen(false)}
        initialScope={pdfExportScope}
        metrics={metrics}
        users={users}
        alerts={alerts}
        auditLogs={auditLogs}
        fgaEvents={fgaEvents}
        triggers={triggers}
        defaultPrivacyMode={privacyMode}
        onExportSuccess={(filename, pageCount, scope) => {
          const label =
            scope === 'alerts'
              ? 'Báo cáo Cảnh báo IDS'
              : scope === 'audit'
              ? 'Nhật ký Kiểm toán Audit Log'
              : 'Hồ sơ Bảo mật Tổng hợp SOC';
          addToast(
            `Đã xuất thành công ${label} (${pageCount} trang A4) -> ${filename}!`,
            'success'
          );
        }}
      />

      {/* Toast Notifications */}
      <Toast toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
