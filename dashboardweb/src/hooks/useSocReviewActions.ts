import { useCallback } from 'react';
import {
  AlertItem,
  AuditLogRow,
  DbUser,
  FgaEvent,
  TriggerAlert,
  getAuditKey,
  getFgaKey,
} from '../types/ids';
import { recalculateUsersAfterReset } from '../utils/analytics';
import { maskUsername } from '../utils/privacy';
import {
  UseIdsTelemetryResult,
  ToastType,
  addCappedToSet,
  formatUtcTimestamp,
} from './useIdsTelemetry';

export interface UseSocReviewActionsOptions {
  telemetry: UseIdsTelemetryResult;
  addToast: (message: string, type?: ToastType) => void;
}

interface ParsedMutationResult {
  ok: boolean;
  status: number;
  errorMessage: string;
}

function restoreSet<T>(target: Set<T>, snapshot: Set<T>): void {
  target.clear();
  snapshot.forEach((item) => target.add(item));
}

async function parseMutationResponse(
  res: Response | null,
  fallbackMessage: string
): Promise<ParsedMutationResult> {
  if (!res) {
    return {
      ok: false,
      status: 0,
      errorMessage: 'Không thể kết nối máy chủ SOC. Vui lòng kiểm tra kết nối và thử lại.',
    };
  }

  let body: { ok?: boolean; error?: unknown; message?: unknown } | null = null;
  try {
    body = (await res.json()) as { ok?: boolean; error?: unknown; message?: unknown };
  } catch {
    body = null;
  }

  if (res.ok && body?.ok !== false) {
    return { ok: true, status: res.status, errorMessage: '' };
  }

  const parsedMsg =
    (typeof body?.error === 'string' && body.error.trim()) ||
    (typeof body?.message === 'string' && body.message.trim());

  if (res.status === 401) {
    return {
      ok: false,
      status: 401,
      errorMessage: parsedMsg || 'Phiên xác thực SOC đã hết hạn. Vui lòng đăng nhập lại.',
    };
  }
  if (res.status === 403) {
    return {
      ok: false,
      status: 403,
      errorMessage: parsedMsg || 'Yêu cầu bị từ chối bởi kiểm tra bảo mật CSRF (HTTP 403).',
    };
  }

  return {
    ok: false,
    status: res.status,
    errorMessage: parsedMsg || `${fallbackMessage} (HTTP ${res.status})`,
  };
}

export function useSocReviewActions({ telemetry, addToast }: UseSocReviewActionsOptions) {
  const {
    alerts,
    setAlerts,
    fgaEvents,
    setFgaEvents,
    triggers,
    setTriggers,
    auditLogs,
    setAuditLogs,
    setUsers,
    autoResponse,
    setAutoResponse,
    activeMode,
    setIsBridgeConnected,
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
    postAuthenticatedJson,
    runWithMutationLock,
  } = telemetry;

  const executeVerifiedMutation = useCallback(
    async ({
      url,
      body,
      fallbackError,
      onRollback,
      onSuccess,
    }: {
      url: string;
      body: unknown;
      fallbackError: string;
      onRollback?: (status: number) => void;
      onSuccess?: () => void;
    }): Promise<boolean> => {
      const res = await runWithMutationLock(() => postAuthenticatedJson(url, body));
      const result = await parseMutationResponse(res, fallbackError);

      if (!result.ok) {
        onRollback?.(result.status);
        if (result.status === 0) {
          setIsBridgeConnected(false);
        }
        if (result.status === 401) {
          handleUnauthorized?.(result.errorMessage);
        }
        addToast(result.errorMessage, 'error');
        if (result.status !== 401) {
          await syncFromOracleBackend(false);
        }
        return false;
      }

      onSuccess?.();
      return true;
    },
    [
      runWithMutationLock,
      postAuthenticatedJson,
      setIsBridgeConnected,
      handleUnauthorized,
      addToast,
      syncFromOracleBackend,
    ]
  );

  const syncReviewStateToServer = useCallback(
    async (onRollback?: () => void): Promise<boolean> => {
      const payload = {
        reviewed_alert_keys: Array.from(reviewedKeysRef.current),
        reviewed_fga_keys: Array.from(reviewedFgaKeysRef.current),
        reviewed_trigger_ids: Array.from(reviewedTriggerIdsRef.current),
        reviewed_audit_keys: Array.from(reviewedAuditKeysRef.current),
      };
      return executeVerifiedMutation({
        url: '/api/review-state',
        body: payload,
        fallbackError: 'Không thể lưu trạng thái kiểm duyệt lên máy chủ',
        onRollback: onRollback ? () => onRollback() : undefined,
      });
    },
    [
      reviewedKeysRef,
      reviewedFgaKeysRef,
      reviewedTriggerIdsRef,
      reviewedAuditKeysRef,
      executeVerifiedMutation,
    ]
  );

  const handleUserAction = useCallback(
    (username: string, action: 'lock' | 'unlock' | 'revoke_dml' | 'grant_dml') => {
      const nowStr = formatUtcTimestamp();
      const targetUpper = username.trim().toUpperCase();
      let prevUsersSnapshot: DbUser[] = [];

      setUsers((prev) => {
        prevUsersSnapshot = prev;
        return prev.map((u) => {
          if (u.USERNAME.toUpperCase() !== targetUpper) return u;
          if (action === 'lock') {
            return {
              ...u,
              ACCOUNT_STATUS: 'LOCKED',
              LOCK_DATE: nowStr,
              RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 3),
              RESPONSE_LABEL: 'Level 3: CRITICAL (Full Isolation)',
            };
          }
          if (action === 'unlock') {
            return {
              ...u,
              ACCOUNT_STATUS: 'OPEN',
              RISK_SCORE: 0,
              RESPONSE_LEVEL: 0,
              RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
              LOCK_DATE: undefined,
            };
          }
          if (action === 'revoke_dml') {
            return {
              ...u,
              DML_STATUS: 'READ-ONLY',
              PRIVILEGES: 'SELECT',
              RESPONSE_LEVEL: Math.max(u.RESPONSE_LEVEL, 2),
              RESPONSE_LABEL: 'Level 2: HIGH (Privilege Containment)',
            };
          }
          return {
            ...u,
            DML_STATUS: 'FULL DML',
            PRIVILEGES: 'DELETE, INSERT, SELECT, UPDATE',
            RISK_SCORE: 0,
            RESPONSE_LEVEL: 0,
            RESPONSE_LABEL: 'Level 0: Normal (An toàn)',
          };
        });
      });

      const displayUser = maskUsername(username, privacyModeRef.current);

      void executeVerifiedMutation({
        url: '/api/user-action',
        body: { username, action },
        fallbackError: `Không thể thực hiện thao tác '${action}' cho tài khoản ${displayUser}`,
        onRollback: () => setUsers(prevUsersSnapshot),
        onSuccess: () => {
          if ((action === 'unlock' || action === 'grant_dml') && activeMode !== 'oracle_live') {
            if (markSimUserCleared) {
              markSimUserCleared(username, nowStr);
            } else if (simUserClearedAtRef?.current) {
              simUserClearedAtRef.current[targetUpper] = nowStr;
            }
          }

          if (action === 'lock') {
            addToast(
              `[Level 3 - Full Isolation] Đã KHÓA tài khoản ${displayUser} và ngắt kết nối phiên!`,
              'error'
            );
          } else if (action === 'unlock') {
            addToast(`Đã MỞ KHÓA tài khoản ${displayUser} và đặt lại Risk Score = 0!`, 'success');
          } else if (action === 'revoke_dml') {
            addToast(
              `[Level 2 - Privilege Containment] Đã thu hồi quyền DML của ${displayUser} -> Chuyển về READ-ONLY!`,
              'error'
            );
          } else {
            addToast(
              `Đã KHÔI PHỤC đầy đủ quyền DML (SELECT, INSERT, UPDATE, DELETE) cho ${displayUser} và đặt lại Risk Score = 0!`,
              'success'
            );
          }
        },
      });
    },
    [
      setUsers,
      privacyModeRef,
      executeVerifiedMutation,
      activeMode,
      markSimUserCleared,
      simUserClearedAtRef,
      addToast,
    ]
  );

  // 1. Alerts Review & Reset
  const handleToggleReviewAlert = useCallback(
    (key: string) => {
      const prevAlerts = alerts;
      const prevReviewed = new Set(reviewedKeysRef.current);
      const current = alerts.find((a) => a.key === key);
      const nextReviewed = !(current?.reviewed ?? reviewedKeysRef.current.has(key));
      if (nextReviewed) addCappedToSet(reviewedKeysRef.current, key);
      else reviewedKeysRef.current.delete(key);

      setAlerts((prev) =>
        prev.map((a) => (a.key === key ? { ...a, reviewed: nextReviewed } : a))
      );
      void syncReviewStateToServer(() => {
        restoreSet(reviewedKeysRef.current, prevReviewed);
        setAlerts(prevAlerts);
      });
    },
    [alerts, reviewedKeysRef, setAlerts, syncReviewStateToServer]
  );

  const handleMarkAllAlertsReviewed = useCallback(() => {
    const prevAlerts = alerts;
    const prevReviewed = new Set(reviewedKeysRef.current);
    alerts.forEach((a) => addCappedToSet(reviewedKeysRef.current, a.key));
    setAlerts((prev) => prev.map((a) => ({ ...a, reviewed: true })));

    void syncReviewStateToServer(() => {
      restoreSet(reviewedKeysRef.current, prevReviewed);
      setAlerts(prevAlerts);
    }).then((ok) => {
      if (ok) {
        addToast(`Đã đánh dấu kiểm duyệt tất cả ${alerts.length} cảnh báo IDS!`, 'success');
      }
    });
  }, [alerts, reviewedKeysRef, setAlerts, syncReviewStateToServer, addToast]);

  const handleResetReviewedAlerts = useCallback(() => {
    const prevAlerts = alerts;
    const prevReviewed = new Set(reviewedKeysRef.current);
    let prevUsersSnapshot: DbUser[] = [];

    const reviewedKeys = alerts.filter((a) => a.reviewed).map((a) => a.key);
    reviewedKeys.forEach((k) => reviewedKeysRef.current.delete(k));
    const remaining = alerts.filter((a) => !a.reviewed);
    const removedCount = alerts.length - remaining.length;
    const effectiveAutoResponse = activeMode === 'oracle_live' ? false : autoResponse;

    setAlerts(remaining);
    setUsers((prevUsers) => {
      prevUsersSnapshot = prevUsers;
      return recalculateUsersAfterReset(prevUsers, remaining, effectiveAutoResponse);
    });

    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body: { target: 'reviewed', reviewed_keys: reviewedKeys },
      fallbackError: 'Không thể xóa các cảnh báo đã kiểm duyệt',
      onRollback: () => {
        restoreSet(reviewedKeysRef.current, prevReviewed);
        setAlerts(prevAlerts);
        setUsers(prevUsersSnapshot);
      },
      onSuccess: () => {
        addToast(
          `Đã xóa vĩnh viễn ${removedCount} cảnh báo đã kiểm duyệt khỏi bộ nhớ và cập nhật lại điểm rủi ro!`,
          'success'
        );
      },
    });
  }, [
    alerts,
    reviewedKeysRef,
    activeMode,
    autoResponse,
    setAlerts,
    setUsers,
    executeVerifiedMutation,
    addToast,
  ]);

  const handleDismissSingleAlert = useCallback(
    (key: string) => {
      const prevAlerts = alerts;
      const prevReviewed = new Set(reviewedKeysRef.current);
      let prevUsersSnapshot: DbUser[] = [];

      reviewedKeysRef.current.delete(key);
      const remaining = alerts.filter((a) => a.key !== key);
      const effectiveAutoResponse = activeMode === 'oracle_live' ? false : autoResponse;

      setAlerts(remaining);
      setUsers((prevUsers) => {
        prevUsersSnapshot = prevUsers;
        return recalculateUsersAfterReset(prevUsers, remaining, effectiveAutoResponse);
      });

      void executeVerifiedMutation({
        url: '/api/clear-alerts',
        body: { target: 'single_ids', alert_key: key },
        fallbackError: 'Không thể xóa cảnh báo IDS khỏi máy chủ',
        onRollback: () => {
          restoreSet(reviewedKeysRef.current, prevReviewed);
          setAlerts(prevAlerts);
          setUsers(prevUsersSnapshot);
        },
        onSuccess: () => {
          addToast('Đã xóa cảnh báo khỏi bộ nhớ và cập nhật lại Risk Score!', 'info');
        },
      });
    },
    [
      alerts,
      reviewedKeysRef,
      activeMode,
      autoResponse,
      setAlerts,
      setUsers,
      executeVerifiedMutation,
      addToast,
    ]
  );

  // 2. FGA Events Review & Reset (Key-based)
  const handleToggleReviewFga = useCallback(
    (fgaKey: string) => {
      const prevFga = fgaEvents;
      const prevReviewed = new Set(reviewedFgaKeysRef.current);
      const current = fgaEvents.find((item) => getFgaKey(item) === fgaKey);
      const nextReviewed = !(current?.reviewed ?? reviewedFgaKeysRef.current.has(fgaKey));
      if (nextReviewed) addCappedToSet(reviewedFgaKeysRef.current, fgaKey);
      else reviewedFgaKeysRef.current.delete(fgaKey);

      setFgaEvents((prev) =>
        prev.map((item) =>
          getFgaKey(item) === fgaKey ? { ...item, reviewed: nextReviewed } : item
        )
      );
      void syncReviewStateToServer(() => {
        restoreSet(reviewedFgaKeysRef.current, prevReviewed);
        setFgaEvents(prevFga);
      });
    },
    [fgaEvents, reviewedFgaKeysRef, setFgaEvents, syncReviewStateToServer]
  );

  const handleMarkAllFgaReviewed = useCallback(() => {
    const prevFga = fgaEvents;
    const prevReviewed = new Set(reviewedFgaKeysRef.current);
    fgaEvents.forEach((item) => addCappedToSet(reviewedFgaKeysRef.current, getFgaKey(item)));
    setFgaEvents((prev) => prev.map((item) => ({ ...item, reviewed: true })));

    void syncReviewStateToServer(() => {
      restoreSet(reviewedFgaKeysRef.current, prevReviewed);
      setFgaEvents(prevFga);
    }).then((ok) => {
      if (ok) {
        addToast(`Đã đánh dấu kiểm duyệt tất cả ${fgaEvents.length} sự kiện FGA!`, 'success');
      }
    });
  }, [fgaEvents, reviewedFgaKeysRef, setFgaEvents, syncReviewStateToServer, addToast]);

  const handleResetReviewedFga = useCallback(() => {
    const prevFga = fgaEvents;
    const prevReviewed = new Set(reviewedFgaKeysRef.current);
    const prevDismissed = new Set(dismissedFgaKeysRef.current);

    const reviewedFga = fgaEvents.filter((item) => item.reviewed).map((item) => getFgaKey(item));
    reviewedFga.forEach((k) => {
      addCappedToSet(dismissedFgaKeysRef.current, k);
      reviewedFgaKeysRef.current.delete(k);
    });
    const remaining = fgaEvents.filter((item) => !item.reviewed);
    const removedCount = fgaEvents.length - remaining.length;

    setFgaEvents(remaining);
    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body: { target: 'reviewed', reviewed_fga_keys: reviewedFga },
      fallbackError: 'Không thể xóa các sự kiện FGA đã kiểm duyệt',
      onRollback: () => {
        restoreSet(reviewedFgaKeysRef.current, prevReviewed);
        restoreSet(dismissedFgaKeysRef.current, prevDismissed);
        setFgaEvents(prevFga);
      },
      onSuccess: () => {
        addToast(`Đã xóa vĩnh viễn ${removedCount} sự kiện FGA đã kiểm duyệt!`, 'success');
      },
    });
  }, [
    fgaEvents,
    dismissedFgaKeysRef,
    reviewedFgaKeysRef,
    setFgaEvents,
    executeVerifiedMutation,
    addToast,
  ]);

  const handleClearSingleFga = useCallback(
    (fgaKey: string) => {
      const prevFga = fgaEvents;
      const prevReviewed = new Set(reviewedFgaKeysRef.current);
      const prevDismissed = new Set(dismissedFgaKeysRef.current);

      addCappedToSet(dismissedFgaKeysRef.current, fgaKey);
      reviewedFgaKeysRef.current.delete(fgaKey);
      setFgaEvents((prev) => prev.filter((item) => getFgaKey(item) !== fgaKey));

      void executeVerifiedMutation({
        url: '/api/clear-alerts',
        body: { target: 'single_fga', fga_key: fgaKey },
        fallbackError: 'Không thể xóa sự kiện FGA khỏi máy chủ',
        onRollback: () => {
          restoreSet(reviewedFgaKeysRef.current, prevReviewed);
          restoreSet(dismissedFgaKeysRef.current, prevDismissed);
          setFgaEvents(prevFga);
        },
        onSuccess: () => {
          addToast('Đã xóa sự kiện FGA khỏi bộ nhớ!', 'info');
        },
      });
    },
    [
      fgaEvents,
      dismissedFgaKeysRef,
      reviewedFgaKeysRef,
      setFgaEvents,
      executeVerifiedMutation,
      addToast,
    ]
  );

  const handleClearAllFga = useCallback(() => {
    const prevFga = fgaEvents;
    const prevReviewed = new Set(reviewedFgaKeysRef.current);
    const prevDismissed = new Set(dismissedFgaKeysRef.current);
    const prevCutoff = fgaCutoffRef.current;

    fgaEvents.forEach((item) => addCappedToSet(dismissedFgaKeysRef.current, getFgaKey(item)));
    reviewedFgaKeysRef.current.clear();
    const nowStr = formatUtcTimestamp();
    fgaCutoffRef.current = nowStr;
    setFgaEvents([]);

    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body: { target: 'fga', cutoff: nowStr },
      fallbackError: 'Không thể xóa toàn bộ sự kiện FGA',
      onRollback: () => {
        restoreSet(reviewedFgaKeysRef.current, prevReviewed);
        restoreSet(dismissedFgaKeysRef.current, prevDismissed);
        fgaCutoffRef.current = prevCutoff;
        setFgaEvents(prevFga);
      },
      onSuccess: () => {
        addToast('Đã xóa toàn bộ danh sách sự kiện FGA khỏi bộ nhớ!', 'success');
      },
    });
  }, [
    fgaEvents,
    dismissedFgaKeysRef,
    reviewedFgaKeysRef,
    fgaCutoffRef,
    setFgaEvents,
    executeVerifiedMutation,
    addToast,
  ]);

  // 3. Trigger Alerts Review & Reset
  const handleToggleReviewTrigger = useCallback(
    (alertId: number) => {
      const prevTriggers = triggers;
      const prevReviewed = new Set(reviewedTriggerIdsRef.current);
      const current = triggers.find((t) => t.ALERT_ID === alertId);
      const nextReviewed = !(current?.reviewed ?? reviewedTriggerIdsRef.current.has(alertId));
      if (nextReviewed) addCappedToSet(reviewedTriggerIdsRef.current, alertId);
      else reviewedTriggerIdsRef.current.delete(alertId);

      setTriggers((prev) =>
        prev.map((t) => (t.ALERT_ID === alertId ? { ...t, reviewed: nextReviewed } : t))
      );
      void syncReviewStateToServer(() => {
        restoreSet(reviewedTriggerIdsRef.current, prevReviewed);
        setTriggers(prevTriggers);
      });
    },
    [triggers, reviewedTriggerIdsRef, setTriggers, syncReviewStateToServer]
  );

  const handleMarkAllTriggersReviewed = useCallback(() => {
    const prevTriggers = triggers;
    const prevReviewed = new Set(reviewedTriggerIdsRef.current);
    triggers.forEach((t) => addCappedToSet(reviewedTriggerIdsRef.current, t.ALERT_ID));
    setTriggers((prev) => prev.map((t) => ({ ...t, reviewed: true })));

    void syncReviewStateToServer(() => {
      restoreSet(reviewedTriggerIdsRef.current, prevReviewed);
      setTriggers(prevTriggers);
    }).then((ok) => {
      if (ok) {
        addToast(`Đã đánh dấu kiểm duyệt tất cả ${triggers.length} bản ghi Trigger!`, 'success');
      }
    });
  }, [triggers, reviewedTriggerIdsRef, setTriggers, syncReviewStateToServer, addToast]);

  const handleResetReviewedTriggers = useCallback(() => {
    const prevTriggers = triggers;
    const prevReviewed = new Set(reviewedTriggerIdsRef.current);
    const prevDismissed = new Set(dismissedTriggerIdsRef.current);

    const reviewedTrigIds = triggers.filter((t) => t.reviewed).map((t) => t.ALERT_ID);
    reviewedTrigIds.forEach((id) => {
      addCappedToSet(dismissedTriggerIdsRef.current, id);
      reviewedTriggerIdsRef.current.delete(id);
    });
    const remaining = triggers.filter((t) => !t.reviewed);
    const removedCount = triggers.length - remaining.length;

    setTriggers(remaining);
    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body: { target: 'reviewed', reviewed_trigger_ids: reviewedTrigIds },
      fallbackError: 'Không thể xóa các bản ghi Trigger đã kiểm duyệt',
      onRollback: () => {
        restoreSet(reviewedTriggerIdsRef.current, prevReviewed);
        restoreSet(dismissedTriggerIdsRef.current, prevDismissed);
        setTriggers(prevTriggers);
      },
      onSuccess: () => {
        addToast(
          `Đã xóa vĩnh viễn ${removedCount} bản ghi Trigger đã kiểm duyệt khỏi CSDL!`,
          'success'
        );
      },
    });
  }, [
    triggers,
    dismissedTriggerIdsRef,
    reviewedTriggerIdsRef,
    setTriggers,
    executeVerifiedMutation,
    addToast,
  ]);

  const handleClearSingleTrigger = useCallback(
    (alertId: number) => {
      const prevTriggers = triggers;
      const prevReviewed = new Set(reviewedTriggerIdsRef.current);
      const prevDismissed = new Set(dismissedTriggerIdsRef.current);

      addCappedToSet(dismissedTriggerIdsRef.current, alertId);
      reviewedTriggerIdsRef.current.delete(alertId);
      setTriggers((prev) => prev.filter((t) => t.ALERT_ID !== alertId));

      void executeVerifiedMutation({
        url: '/api/clear-alerts',
        body: { target: 'single_trigger', alert_id: alertId },
        fallbackError: `Không thể xóa bản ghi Trigger #${alertId}`,
        onRollback: () => {
          restoreSet(reviewedTriggerIdsRef.current, prevReviewed);
          restoreSet(dismissedTriggerIdsRef.current, prevDismissed);
          setTriggers(prevTriggers);
        },
        onSuccess: () => {
          addToast(`Đã xóa vĩnh viễn bản ghi Trigger #${alertId} khỏi CSDL!`, 'info');
        },
      });
    },
    [
      triggers,
      dismissedTriggerIdsRef,
      reviewedTriggerIdsRef,
      setTriggers,
      executeVerifiedMutation,
      addToast,
    ]
  );

  // 4. Unified Audit Trail Review & Reset (Key-based)
  const handleToggleReviewAudit = useCallback(
    (auditKey: string) => {
      const prevAudit = auditLogs;
      const prevReviewed = new Set(reviewedAuditKeysRef.current);
      const current = auditLogs.find((row) => getAuditKey(row) === auditKey);
      const nextReviewed = !(current?.reviewed ?? reviewedAuditKeysRef.current.has(auditKey));
      if (nextReviewed) addCappedToSet(reviewedAuditKeysRef.current, auditKey);
      else reviewedAuditKeysRef.current.delete(auditKey);

      setAuditLogs((prev) =>
        prev.map((row) =>
          getAuditKey(row) === auditKey ? { ...row, reviewed: nextReviewed } : row
        )
      );
      void syncReviewStateToServer(() => {
        restoreSet(reviewedAuditKeysRef.current, prevReviewed);
        setAuditLogs(prevAudit);
      });
    },
    [auditLogs, reviewedAuditKeysRef, setAuditLogs, syncReviewStateToServer]
  );

  const handleMarkAllAuditReviewed = useCallback(() => {
    const prevAudit = auditLogs;
    const prevReviewed = new Set(reviewedAuditKeysRef.current);
    auditLogs.forEach((r) => addCappedToSet(reviewedAuditKeysRef.current, getAuditKey(r)));
    setAuditLogs((prev) => prev.map((row) => ({ ...row, reviewed: true })));

    void syncReviewStateToServer(() => {
      restoreSet(reviewedAuditKeysRef.current, prevReviewed);
      setAuditLogs(prevAudit);
    }).then((ok) => {
      if (ok) {
        addToast(`Đã đánh dấu kiểm duyệt toàn bộ ${auditLogs.length} bản ghi Audit Log!`, 'success');
      }
    });
  }, [auditLogs, reviewedAuditKeysRef, setAuditLogs, syncReviewStateToServer, addToast]);

  const handleResetReviewedAudit = useCallback(() => {
    const prevAudit = auditLogs;
    const prevReviewed = new Set(reviewedAuditKeysRef.current);
    const prevCutoff = auditCutoffRef.current;

    const reviewedAudKeys = auditLogs
      .filter((row) => row.reviewed)
      .map((row) => getAuditKey(row));
    reviewedAudKeys.forEach((k) => reviewedAuditKeysRef.current.delete(k));
    const remaining = auditLogs.filter((row) => !row.reviewed);
    const removedCount = auditLogs.length - remaining.length;

    setAuditLogs(remaining);
    const nowStr = formatUtcTimestamp();
    if (remaining.length === 0) {
      auditCutoffRef.current = nowStr;
    }

    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body:
        remaining.length === 0
          ? { target: 'audit', cutoff: nowStr }
          : { target: 'reviewed', reviewed_audit_keys: reviewedAudKeys, cutoff: nowStr },
      fallbackError: 'Không thể xóa các bản ghi Audit Log đã kiểm duyệt',
      onRollback: () => {
        restoreSet(reviewedAuditKeysRef.current, prevReviewed);
        auditCutoffRef.current = prevCutoff;
        setAuditLogs(prevAudit);
      },
      onSuccess: () => {
        addToast(`Đã xóa vĩnh viễn ${removedCount} bản ghi Audit Log đã kiểm duyệt!`, 'success');
      },
    });
  }, [
    auditLogs,
    reviewedAuditKeysRef,
    setAuditLogs,
    auditCutoffRef,
    executeVerifiedMutation,
    addToast,
  ]);

  const handleClearSingleAudit = useCallback(
    (auditKey: string) => {
      const prevAudit = auditLogs;
      const prevReviewed = new Set(reviewedAuditKeysRef.current);

      reviewedAuditKeysRef.current.delete(auditKey);
      setAuditLogs((prev) => prev.filter((row) => getAuditKey(row) !== auditKey));

      void executeVerifiedMutation({
        url: '/api/clear-alerts',
        body: { target: 'single_audit', audit_key: auditKey },
        fallbackError: 'Không thể xóa bản ghi Unified Audit Trail',
        onRollback: () => {
          restoreSet(reviewedAuditKeysRef.current, prevReviewed);
          setAuditLogs(prevAudit);
        },
        onSuccess: () => {
          addToast('Đã xóa bản ghi Unified Audit Trail khỏi bộ nhớ!', 'info');
        },
      });
    },
    [auditLogs, reviewedAuditKeysRef, setAuditLogs, executeVerifiedMutation, addToast]
  );

  const handleClearAllAudit = useCallback(() => {
    const prevAudit = auditLogs;
    const prevReviewed = new Set(reviewedAuditKeysRef.current);
    const prevCutoff = auditCutoffRef.current;

    setAuditLogs([]);
    reviewedAuditKeysRef.current.clear();
    const nowStr = formatUtcTimestamp();
    auditCutoffRef.current = nowStr;

    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body: { target: 'audit', cutoff: nowStr },
      fallbackError: 'Không thể xóa toàn bộ nhật ký Unified Audit Trail',
      onRollback: () => {
        restoreSet(reviewedAuditKeysRef.current, prevReviewed);
        auditCutoffRef.current = prevCutoff;
        setAuditLogs(prevAudit);
      },
      onSuccess: () => {
        addToast('Đã xóa toàn bộ nhật ký Unified Audit Trail và giải phóng bộ nhớ!', 'success');
      },
    });
  }, [
    auditLogs,
    setAuditLogs,
    reviewedAuditKeysRef,
    auditCutoffRef,
    executeVerifiedMutation,
    addToast,
  ]);

  // 5. Global Overview Review & Reset
  const handleMarkAllSystemReviewed = useCallback(() => {
    const prevAlerts = alerts;
    const prevFga = fgaEvents;
    const prevTriggers = triggers;
    const prevAudit = auditLogs;
    const prevAlertKeys = new Set(reviewedKeysRef.current);
    const prevFgaKeys = new Set(reviewedFgaKeysRef.current);
    const prevTrigIds = new Set(reviewedTriggerIdsRef.current);
    const prevAuditKeys = new Set(reviewedAuditKeysRef.current);

    alerts.forEach((a) => addCappedToSet(reviewedKeysRef.current, a.key));
    fgaEvents.forEach((f) => addCappedToSet(reviewedFgaKeysRef.current, getFgaKey(f)));
    triggers.forEach((t) => addCappedToSet(reviewedTriggerIdsRef.current, t.ALERT_ID));
    auditLogs.forEach((r) => addCappedToSet(reviewedAuditKeysRef.current, getAuditKey(r)));

    setAlerts((prev) => prev.map((a) => ({ ...a, reviewed: true })));
    setFgaEvents((prev) => prev.map((f) => ({ ...f, reviewed: true })));
    setTriggers((prev) => prev.map((t) => ({ ...t, reviewed: true })));
    setAuditLogs((prev) => prev.map((r) => ({ ...r, reviewed: true })));

    void syncReviewStateToServer(() => {
      restoreSet(reviewedKeysRef.current, prevAlertKeys);
      restoreSet(reviewedFgaKeysRef.current, prevFgaKeys);
      restoreSet(reviewedTriggerIdsRef.current, prevTrigIds);
      restoreSet(reviewedAuditKeysRef.current, prevAuditKeys);
      setAlerts(prevAlerts);
      setFgaEvents(prevFga);
      setTriggers(prevTriggers);
      setAuditLogs(prevAudit);
    }).then((ok) => {
      if (ok) {
        addToast(
          'Đã đánh dấu ĐÃ KIỂM DUYỆT cho toàn bộ Cảnh báo, FGA, Trigger và Audit Log!',
          'success'
        );
      }
    });
  }, [
    alerts,
    fgaEvents,
    triggers,
    auditLogs,
    reviewedKeysRef,
    reviewedFgaKeysRef,
    reviewedTriggerIdsRef,
    reviewedAuditKeysRef,
    setAlerts,
    setFgaEvents,
    setTriggers,
    setAuditLogs,
    syncReviewStateToServer,
    addToast,
  ]);

  const handleResetAllReviewedSystem = useCallback(() => {
    const prevAlerts = alerts;
    const prevFga = fgaEvents;
    const prevTriggers = triggers;
    const prevAudit = auditLogs;
    let prevUsersSnapshot: DbUser[] = [];
    const prevAlertKeys = new Set(reviewedKeysRef.current);
    const prevFgaKeys = new Set(reviewedFgaKeysRef.current);
    const prevDismissedFga = new Set(dismissedFgaKeysRef.current);
    const prevTrigIds = new Set(reviewedTriggerIdsRef.current);
    const prevDismissedTrig = new Set(dismissedTriggerIdsRef.current);
    const prevAuditKeys = new Set(reviewedAuditKeysRef.current);
    const prevAuditCutoff = auditCutoffRef.current;
    const prevFgaCutoff = fgaCutoffRef.current;

    const reviewedKeys = alerts.filter((a) => a.reviewed).map((a) => a.key);
    const reviewedFga = fgaEvents.filter((f) => f.reviewed).map((f) => getFgaKey(f));
    const reviewedTrigIds = triggers.filter((t) => t.reviewed).map((t) => t.ALERT_ID);
    const reviewedAudKeys = auditLogs.filter((r) => r.reviewed).map((r) => getAuditKey(r));

    reviewedKeys.forEach((k) => reviewedKeysRef.current.delete(k));
    reviewedFga.forEach((k) => {
      addCappedToSet(dismissedFgaKeysRef.current, k);
      reviewedFgaKeysRef.current.delete(k);
    });
    reviewedTrigIds.forEach((id) => {
      addCappedToSet(dismissedTriggerIdsRef.current, id);
      reviewedTriggerIdsRef.current.delete(id);
    });
    reviewedAudKeys.forEach((k) => reviewedAuditKeysRef.current.delete(k));

    const remainingAlerts = alerts.filter((a) => !a.reviewed);
    const remainingFga = fgaEvents.filter((f) => !f.reviewed);
    const remainingTriggers = triggers.filter((t) => !t.reviewed);
    const remainingAudit = auditLogs.filter((r) => !r.reviewed);

    const isEverythingCleared =
      remainingAlerts.length === 0 &&
      remainingFga.length === 0 &&
      remainingTriggers.length === 0 &&
      remainingAudit.length === 0;
    const effectiveAutoResponse =
      !isEverythingCleared && activeMode === 'oracle_live' ? false : autoResponse;

    setAlerts(remainingAlerts);
    setFgaEvents(remainingFga);
    setTriggers(remainingTriggers);
    setAuditLogs(remainingAudit);
    setUsers((prevUsers) => {
      prevUsersSnapshot = prevUsers;
      return recalculateUsersAfterReset(prevUsers, remainingAlerts, effectiveAutoResponse);
    });

    const nowStr = formatUtcTimestamp();
    if (remainingAudit.length === 0) auditCutoffRef.current = nowStr;
    if (remainingFga.length === 0) fgaCutoffRef.current = nowStr;

    void executeVerifiedMutation({
      url: '/api/clear-alerts',
      body: isEverythingCleared
        ? { target: 'all', cutoff: nowStr }
        : {
            target: 'reviewed',
            reviewed_keys: reviewedKeys,
            reviewed_fga_keys: reviewedFga,
            reviewed_trigger_ids: reviewedTrigIds,
            reviewed_audit_keys: reviewedAudKeys,
            cutoff: nowStr,
          },
      fallbackError: 'Không thể xóa toàn bộ các mục đã kiểm duyệt',
      onRollback: () => {
        restoreSet(reviewedKeysRef.current, prevAlertKeys);
        restoreSet(reviewedFgaKeysRef.current, prevFgaKeys);
        restoreSet(dismissedFgaKeysRef.current, prevDismissedFga);
        restoreSet(reviewedTriggerIdsRef.current, prevTrigIds);
        restoreSet(dismissedTriggerIdsRef.current, prevDismissedTrig);
        restoreSet(reviewedAuditKeysRef.current, prevAuditKeys);
        auditCutoffRef.current = prevAuditCutoff;
        fgaCutoffRef.current = prevFgaCutoff;
        setAlerts(prevAlerts);
        setFgaEvents(prevFga);
        setTriggers(prevTriggers);
        setAuditLogs(prevAudit);
        setUsers(prevUsersSnapshot);
      },
      onSuccess: () => {
        if (isEverythingCleared && activeMode !== 'oracle_live') {
          clearSimUserClearedState?.();
        }
        addToast(
          'Đã xóa vĩnh viễn toàn bộ mục đã kiểm duyệt khỏi bộ nhớ và cập nhật lại điểm rủi ro!',
          'success'
        );
      },
    });
  }, [
    alerts,
    fgaEvents,
    triggers,
    auditLogs,
    reviewedKeysRef,
    dismissedFgaKeysRef,
    reviewedFgaKeysRef,
    dismissedTriggerIdsRef,
    reviewedTriggerIdsRef,
    reviewedAuditKeysRef,
    setAlerts,
    setFgaEvents,
    setTriggers,
    setAuditLogs,
    setUsers,
    activeMode,
    autoResponse,
    auditCutoffRef,
    fgaCutoffRef,
    executeVerifiedMutation,
    clearSimUserClearedState,
    addToast,
  ]);

  const handleClearAlerts = useCallback(
    (target: 'ids' | 'triggers' | 'all') => {
      const nowStr = formatUtcTimestamp();
      const prevAlerts = alerts;
      const prevFga = fgaEvents;
      const prevTriggers = triggers;
      const prevAudit = auditLogs;
      let prevUsersSnapshot: DbUser[] = [];

      const prevAlertKeys = new Set(reviewedKeysRef.current);
      const prevFgaKeys = new Set(reviewedFgaKeysRef.current);
      const prevDismissedFga = new Set(dismissedFgaKeysRef.current);
      const prevTrigIds = new Set(reviewedTriggerIdsRef.current);
      const prevDismissedTrig = new Set(dismissedTriggerIdsRef.current);
      const prevAuditKeys = new Set(reviewedAuditKeysRef.current);
      const prevAuditCutoff = auditCutoffRef.current;
      const prevFgaCutoff = fgaCutoffRef.current;

      if (target === 'all') {
        auditCutoffRef.current = nowStr;
        fgaCutoffRef.current = nowStr;
        fgaEvents.forEach((f) => addCappedToSet(dismissedFgaKeysRef.current, getFgaKey(f)));
        triggers.forEach((t) => addCappedToSet(dismissedTriggerIdsRef.current, t.ALERT_ID));
        reviewedKeysRef.current.clear();
        reviewedFgaKeysRef.current.clear();
        reviewedTriggerIdsRef.current.clear();
        reviewedAuditKeysRef.current.clear();
        setAlerts([]);
        setTriggers([]);
        setFgaEvents([]);
        setAuditLogs([]);
        setUsers((prevUsers) => {
          prevUsersSnapshot = prevUsers;
          return recalculateUsersAfterReset(prevUsers, [], autoResponse);
        });
      } else if (target === 'triggers') {
        triggers.forEach((t) => addCappedToSet(dismissedTriggerIdsRef.current, t.ALERT_ID));
        reviewedTriggerIdsRef.current.clear();
        setTriggers([]);
      } else {
        reviewedKeysRef.current.clear();
        setAlerts([]);
        setUsers((prevUsers) => {
          prevUsersSnapshot = prevUsers;
          return recalculateUsersAfterReset(prevUsers, [], autoResponse);
        });
      }

      void executeVerifiedMutation({
        url: '/api/clear-alerts',
        body: { target, cutoff: nowStr },
        fallbackError: 'Không thể dọn dữ liệu cảnh báo trên máy chủ',
        onRollback: () => {
          restoreSet(reviewedKeysRef.current, prevAlertKeys);
          restoreSet(reviewedFgaKeysRef.current, prevFgaKeys);
          restoreSet(dismissedFgaKeysRef.current, prevDismissedFga);
          restoreSet(reviewedTriggerIdsRef.current, prevTrigIds);
          restoreSet(dismissedTriggerIdsRef.current, prevDismissedTrig);
          restoreSet(reviewedAuditKeysRef.current, prevAuditKeys);
          auditCutoffRef.current = prevAuditCutoff;
          fgaCutoffRef.current = prevFgaCutoff;
          setAlerts(prevAlerts);
          setFgaEvents(prevFga);
          setTriggers(prevTriggers);
          setAuditLogs(prevAudit);
          if (target === 'ids' || target === 'all') {
            setUsers(prevUsersSnapshot);
          }
        },
        onSuccess: () => {
          if ((target === 'ids' || target === 'all') && activeMode !== 'oracle_live') {
            clearSimUserClearedState?.();
          }
          if (target === 'ids') {
            addToast(
              'Đã Reset toàn bộ cảnh báo IDS và khôi phục trạng thái an toàn (Risk = 0) cho User!',
              'success'
            );
          } else if (target === 'triggers') {
            addToast('Đã Reset nhật ký vi phạm Trigger!', 'success');
          } else {
            addToast(
              'Đã hoàn tất kiểm duyệt & Reset toàn bộ Cảnh báo IDS, Bẫy FGA, Trigger và sẵn sàng nhận cảnh báo mới từ Oracle SQL Developer!',
              'success'
            );
          }
        },
      });
    },
    [
      alerts,
      fgaEvents,
      triggers,
      auditLogs,
      auditCutoffRef,
      fgaCutoffRef,
      dismissedFgaKeysRef,
      dismissedTriggerIdsRef,
      reviewedKeysRef,
      reviewedFgaKeysRef,
      reviewedTriggerIdsRef,
      reviewedAuditKeysRef,
      executeVerifiedMutation,
      setAlerts,
      setUsers,
      setTriggers,
      setFgaEvents,
      setAuditLogs,
      autoResponse,
      activeMode,
      clearSimUserClearedState,
      addToast,
    ]
  );

  const handleToggleAutoResponse = useCallback(
    (enabled: boolean) => {
      const prevAutoResponse = autoResponse;
      setAutoResponse(enabled);

      void executeVerifiedMutation({
        url: '/api/toggle-ips',
        body: { auto_response: enabled },
        fallbackError: 'Không thể cập nhật chế độ Tự động Phản ứng IPS',
        onRollback: () => setAutoResponse(prevAutoResponse),
        onSuccess: () => {
          addToast(
            enabled
              ? 'Đã BẬT chế độ Tự động Phản ứng Đa cấp (Graduated IPS Engine)!'
              : 'Đã TẮT chế độ Tự động Phản ứng (Chuyển sang Giám sát Thụ động).',
            'info'
          );
        },
      });
    },
    [autoResponse, setAutoResponse, executeVerifiedMutation, addToast]
  );

  return {
    handleUserAction,
    handleToggleReviewAlert,
    handleMarkAllAlertsReviewed,
    handleResetReviewedAlerts,
    handleDismissSingleAlert,
    handleToggleReviewFga,
    handleMarkAllFgaReviewed,
    handleResetReviewedFga,
    handleClearSingleFga,
    handleClearAllFga,
    handleToggleReviewTrigger,
    handleMarkAllTriggersReviewed,
    handleResetReviewedTriggers,
    handleClearSingleTrigger,
    handleToggleReviewAudit,
    handleMarkAllAuditReviewed,
    handleResetReviewedAudit,
    handleClearSingleAudit,
    handleClearAllAudit,
    handleMarkAllSystemReviewed,
    handleResetAllReviewedSystem,
    handleClearAlerts,
    handleToggleAutoResponse,
  };
}
