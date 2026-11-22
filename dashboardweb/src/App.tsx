/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useCallback } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { Shield } from 'lucide-react';
import { Sidebar } from './components/Sidebar';
import { Header, LayoutWidthMode, UiDensityMode, ThemeMode } from './components/Header';
import { SocAuthGate } from './components/SocAuthGate';
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
import { useIdsTelemetry, ToastType } from './hooks/useIdsTelemetry';
import { useSocReviewActions } from './hooks/useSocReviewActions';
import { calculateSystemMetrics } from './utils/analytics';
import { PdfExportScope } from './utils/pdfExporter';
import { ActiveTab, AlertItem, AuditLogRow, FgaEvent, Metrics, TriggerAlert, getAuditKey } from './types/ids';

function getTriggerReturnCode(attackType: string): number {
  const upper = (attackType || '').toUpperCase();
  if (upper.includes('SALARY')) return 20002;
  if (upper.includes('HONEYTOKEN') || upper.includes('SQL_INJECTION')) return 20003;
  if (upper.includes('INTEGRITY')) return 20004;
  return 20001;
}

function fgaToAuditRow(fga: FgaEvent): AuditLogRow {
  return {
    EVENT_TIMESTAMP: fga.EVENT_TIMESTAMP,
    DBUSERNAME: fga.DBUSERNAME,
    ACTION_NAME: fga.ACTION_NAME || 'SELECT',
    OBJECT_SCHEMA: fga.OBJECT_SCHEMA || 'SYS',
    OBJECT_NAME: fga.OBJECT_NAME || 'NV',
    SQL_TEXT: fga.SQL_TEXT,
    RETURN_CODE: Number(fga.RETURN_CODE || 0),
    OS_USERNAME: fga.OS_USERNAME,
    USERHOST: fga.USERHOST,
    CLIENT_PROGRAM_NAME: fga.CLIENT_PROGRAM_NAME || 'SQL Developer (DBMS_FGA)',
    AUDIT_TYPE: fga.AUDIT_TYPE || 'FineGrainedAudit',
    FGA_POLICY_NAME: fga.FGA_POLICY_NAME,
    reviewed: fga.reviewed,
  };
}

function triggerToAuditRow(trig: TriggerAlert): AuditLogRow {
  return {
    EVENT_TIMESTAMP: trig.EVENT_TIME,
    DBUSERNAME: trig.DB_USER,
    ACTION_NAME: trig.ATTACK_TYPE,
    OBJECT_SCHEMA: 'SYS',
    OBJECT_NAME: 'NV',
    SQL_TEXT: trig.DETAILS,
    RETURN_CODE: getTriggerReturnCode(trig.ATTACK_TYPE),
    OS_USERNAME: 'oracle_session',
    USERHOST: 'FREEPDB1',
    CLIENT_PROGRAM_NAME: 'PL/SQL Trigger (PRAGMA AUTONOMOUS_TRANSACTION)',
    AUDIT_TYPE: 'TriggerAlert',
    reviewed: trig.reviewed,
  };
}

export default function App() {
  const shouldReduceMotion = useReducedMotion();
  const [activeTab, setActiveTab] = useState<ActiveTab>('home');
  const [privacyMode, setPrivacyMode] = useState<boolean>(true);
  const [oracleBridgeOpen, setOracleBridgeOpen] = useState<boolean>(false);
  const [pdfExportOpen, setPdfExportOpen] = useState<boolean>(false);
  const [pdfExportScope, setPdfExportScope] = useState<PdfExportScope>('full');

  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);
  const [layoutWidth, setLayoutWidth] = useState<LayoutWidthMode>('boxed');
  const [uiDensity, setUiDensity] = useState<UiDensityMode>('comfortable');
  const [themeMode, setThemeMode] = useState<ThemeMode>('dark');

  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [selectedAlertKey, setSelectedAlertKey] = useState<string | null>(null);
  const [selectedAuditKey, setSelectedAuditKey] = useState<string | null>(null);
  const [customModalAuditRow, setCustomModalAuditRow] = useState<AuditLogRow | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = useCallback((message: string, type: ToastType = 'success') => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev.slice(-2), { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const telemetry = useIdsTelemetry({ privacyMode, addToast });
  const actions = useSocReviewActions({ telemetry, addToast });

  const selectedAlert = useMemo<AlertItem | null>(
    () => (selectedAlertKey ? telemetry.alerts.find((a) => a.key === selectedAlertKey) ?? null : null),
    [telemetry.alerts, selectedAlertKey]
  );

  const selectedAuditRow = useMemo<AuditLogRow | null>(() => {
    if (customModalAuditRow) return customModalAuditRow;
    if (!selectedAuditKey) return null;
    return telemetry.auditLogs.find((r) => getAuditKey(r) === selectedAuditKey) ?? null;
  }, [customModalAuditRow, telemetry.auditLogs, selectedAuditKey]);

  const metrics: Metrics = useMemo(
    () =>
      calculateSystemMetrics(
        telemetry.auditLogs.length,
        telemetry.alerts.length,
        telemetry.triggers.length,
        telemetry.fgaEvents.length,
        telemetry.users
      ),
    [telemetry.auditLogs.length, telemetry.alerts.length, telemetry.triggers.length, telemetry.fgaEvents.length, telemetry.users]
  );

  const knownUsers = useMemo(
    () => telemetry.users.map((u) => u.USERNAME),
    [telemetry.users]
  );

  const openOracleBridge = () => setOracleBridgeOpen(true);

  const handleOpenPdfModal = (scope?: PdfExportScope) => {
    const resolvedScope = scope ?? (activeTab === 'alerts' ? 'alerts' : activeTab === 'audit' ? 'audit' : 'full');
    setPdfExportScope(resolvedScope);
    setPdfExportOpen(true);
  };

  const handleOpenAlertModal = (alert: AlertItem) => {
    setSelectedAlertKey(alert.key);
    setSelectedAuditKey(null);
    setCustomModalAuditRow(null);
    setModalOpen(true);
  };

  const handleOpenAuditModal = (row: AuditLogRow) => {
    const key = getAuditKey(row);
    const existsInLogs = telemetry.auditLogs.some((r) => getAuditKey(r) === key);
    setSelectedAlertKey(null);
    setSelectedAuditKey(existsInLogs ? key : null);
    setCustomModalAuditRow(existsInLogs ? null : row);
    setModalOpen(true);
  };

  const handleOpenFgaModal = (fga: FgaEvent) => {
    setSelectedAlertKey(null);
    setSelectedAuditKey(null);
    setCustomModalAuditRow(fgaToAuditRow(fga));
    setModalOpen(true);
  };

  const handleOpenTriggerModal = (trig: TriggerAlert) => {
    setSelectedAlertKey(null);
    setSelectedAuditKey(null);
    setCustomModalAuditRow(triggerToAuditRow(trig));
    setModalOpen(true);
  };

  const handleResetAuditRowFromModal = (row: AuditLogRow) => {
    if (selectedAuditKey !== null) {
      actions.handleClearSingleAudit(getAuditKey(row));
      setSelectedAuditKey(null);
    } else if (customModalAuditRow) {
      setCustomModalAuditRow(null);
      addToast('Đã đóng & xác nhận kiểm duyệt bản ghi chi tiết!', 'info');
    }
  };

  const handleTogglePrivacyMode = () => {
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
  };

  const handleToggleThemeMode = () => {
    setThemeMode((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      addToast(
        next === 'light'
          ? 'Đã chuyển sang Chế độ Sáng (Tối ưu hiển thị trên máy chiếu hội đồng bảo vệ)!'
          : 'Đã chuyển sang Chế độ Cyber SOC Tactical Dark!',
        'info'
      );
      return next;
    });
  };

  const themeClass = themeMode === 'light' ? 'theme-light' : '';

  if (!telemetry.authChecked) {
    return (
      <div data-theme={themeMode} className={`min-h-screen soc-canvas-bg flex items-center justify-center p-4 font-sans ${themeClass}`}>
        <div className="flex items-center gap-3 px-5 py-3.5 rounded-xl bg-[var(--surface)] border border-[var(--line)] text-xs text-[var(--text-2)] shadow-lg">
          <Shield className="w-4 h-4 text-[var(--accent)] animate-pulse" />
          <span>Đang kiểm tra phiên xác thực SOC...</span>
        </div>
      </div>
    );
  }

  if (telemetry.authChecked && !telemetry.authenticated) {
    return <SocAuthGate onLogin={telemetry.login} error={telemetry.authError} isLoading={telemetry.isLoggingIn} themeMode={themeMode} />;
  }

  const containerMaxWidthClass =
    layoutWidth === 'fluid' ? 'max-w-none' : layoutWidth === 'compact' ? 'max-w-[1280px]' : 'max-w-[1600px]';

  return (
    <div data-theme={themeMode} className={`min-h-screen soc-canvas-bg text-slate-100 flex flex-col font-sans ${uiDensity === 'compact' ? 'density-compact' : ''} ${themeClass}`}>
      <Sidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        metrics={metrics}
        autoResponse={telemetry.autoResponse}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
        isMobileOpen={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
        onOpenMobile={() => setIsMobileMenuOpen(true)}
      />

      <div className={`flex-1 flex flex-col min-w-0 transition-all duration-200 ease-out ${isSidebarCollapsed ? 'lg:ml-[74px]' : 'lg:ml-64'} ml-0`}>
        <Header
          activeTab={activeTab}
          onRefresh={() => void telemetry.handleRefresh(true)}
          isRefreshing={telemetry.isRefreshing}
          onOpenOracleBridge={openOracleBridge}
          onOpenPdfExport={() => handleOpenPdfModal()}
          isBridgeConnected={telemetry.isBridgeConnected}
          lastSyncTime={telemetry.lastSyncTime}
          privacyMode={privacyMode}
          onTogglePrivacyMode={handleTogglePrivacyMode}
          isSidebarCollapsed={isSidebarCollapsed}
          onToggleSidebarCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
          onOpenMobileMenu={() => setIsMobileMenuOpen(true)}
          layoutWidth={layoutWidth}
          onChangeLayoutWidth={setLayoutWidth}
          uiDensity={uiDensity}
          onChangeUiDensity={setUiDensity}
          themeMode={themeMode}
          onToggleThemeMode={handleToggleThemeMode}
        />

        <main className={`soc-main-container ${uiDensity === 'compact' ? 'p-3 sm:p-4' : 'p-4 sm:p-6'} pb-24 md:pb-12 flex-1 w-full mx-auto transition-all duration-200 ${containerMaxWidthClass}`}>
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={shouldReduceMotion ? false : { opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={shouldReduceMotion ? undefined : { opacity: 0, y: -6 }}
              transition={{ duration: shouldReduceMotion ? 0 : 0.16, ease: [0.16, 1, 0.3, 1] }}
            >
              {activeTab === 'home' && (
                <OverviewTab
                  metrics={metrics} alerts={telemetry.alerts} users={telemetry.users} fgaEvents={telemetry.fgaEvents} triggers={telemetry.triggers} privacyMode={privacyMode} knownUsers={knownUsers}
                  onOpenAlertModal={handleOpenAlertModal} onNavigateTab={setActiveTab} onToggleReviewAlert={actions.handleToggleReviewAlert} onDismissAlert={actions.handleDismissSingleAlert}
                  onMarkAllReviewed={actions.handleMarkAllSystemReviewed} onResetReviewedAll={actions.handleResetAllReviewedSystem} onResetAllAfterAudit={() => actions.handleClearAlerts('all')}
                  onOpenOracleBridge={openOracleBridge} onOpenPdfExport={() => handleOpenPdfModal('full')} onUserAction={actions.handleUserAction}
                />
              )}
              {activeTab === 'alerts' && (
                <AlertsTab
                  alerts={telemetry.alerts} privacyMode={privacyMode} knownUsers={knownUsers} onOpenAlertModal={handleOpenAlertModal} onDismissAlert={actions.handleDismissSingleAlert}
                  onToggleReviewAlert={actions.handleToggleReviewAlert} onMarkAllAlertsReviewed={actions.handleMarkAllAlertsReviewed} onResetReviewedAlerts={actions.handleResetReviewedAlerts}
                  onClearAlerts={actions.handleClearAlerts} onOpenOracleBridge={openOracleBridge} onExportAlertsPdf={() => handleOpenPdfModal('alerts')}
                />
              )}
              {activeTab === 'fga' && (
                <FgaTab
                  fgaEvents={telemetry.fgaEvents} privacyMode={privacyMode} knownUsers={knownUsers} onToggleReviewFga={actions.handleToggleReviewFga} onMarkAllFgaReviewed={actions.handleMarkAllFgaReviewed}
                  onResetReviewedFga={actions.handleResetReviewedFga} onClearSingleFga={actions.handleClearSingleFga} onClearAllFga={actions.handleClearAllFga}
                  onOpenOracleBridge={openOracleBridge} onOpenFgaModal={handleOpenFgaModal}
                />
              )}
              {activeTab === 'triggers' && (
                <TriggersTab
                  triggers={telemetry.triggers} privacyMode={privacyMode} knownUsers={knownUsers} onToggleReviewTrigger={actions.handleToggleReviewTrigger} onMarkAllTriggersReviewed={actions.handleMarkAllTriggersReviewed}
                  onResetReviewedTriggers={actions.handleResetReviewedTriggers} onClearSingleTrigger={actions.handleClearSingleTrigger} onClearAllTriggers={() => actions.handleClearAlerts('triggers')}
                  onOpenOracleBridge={openOracleBridge} onNavigateTab={setActiveTab} onOpenTriggerModal={handleOpenTriggerModal}
                />
              )}
              {activeTab === 'audit' && (
                <AuditTab
                  auditLogs={telemetry.auditLogs} privacyMode={privacyMode} knownUsers={knownUsers} onOpenAuditModal={handleOpenAuditModal} onToggleReviewAudit={actions.handleToggleReviewAudit}
                  onMarkAllAuditReviewed={actions.handleMarkAllAuditReviewed} onResetReviewedAudit={actions.handleResetReviewedAudit} onClearSingleAudit={actions.handleClearSingleAudit}
                  onClearAllAudit={actions.handleClearAllAudit} onOpenOracleBridge={openOracleBridge} onExportAuditPdf={() => handleOpenPdfModal('audit')}
                />
              )}
              {activeTab === 'users' && <UsersTab users={telemetry.users} employees={telemetry.employees} privacyMode={privacyMode} onNavigateTab={setActiveTab} />}
              {activeTab === 'ips' && (
                <IpsTab
                  users={telemetry.users} privacyMode={privacyMode} autoResponse={telemetry.autoResponse} onToggleAutoResponse={actions.handleToggleAutoResponse}
                  autoRefresh={telemetry.autoRefresh}
                  onToggleAutoRefresh={(val) => {
                    telemetry.setAutoRefresh(val);
                    addToast(val ? 'Đã BẬT tự động đồng bộ thời gian thực từ Oracle (3s)!' : 'Đã TẮT tự động đồng bộ định kỳ.', 'info');
                  }}
                  onClearAll={() => actions.handleClearAlerts('all')} onUserAction={actions.handleUserAction}
                />
              )}
              {activeTab === 'docs' && <DocsTab />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <AuditModal
        isOpen={modalOpen} onClose={() => setModalOpen(false)} alertItem={selectedAlert} auditRow={selectedAuditRow} users={telemetry.users} privacyMode={privacyMode}
        onToggleReviewAlert={actions.handleToggleReviewAlert} onResolveAndResetAlert={actions.handleDismissSingleAlert} onResetAuditRow={handleResetAuditRowFromModal} onUserAction={actions.handleUserAction}
      />

      <OracleBridgeModal
        isOpen={oracleBridgeOpen} onClose={() => setOracleBridgeOpen(false)} users={telemetry.users} isBridgeConnected={telemetry.isBridgeConnected} lastSyncTime={telemetry.lastSyncTime}
        privacyMode={privacyMode} dsn={telemetry.dsn} dataSource={telemetry.dataSource} activeMode={telemetry.activeMode} onSwitchMode={telemetry.handleSwitchMode}
        csrfToken={telemetry.csrfToken} onExecuteOracleSql={telemetry.handleExecuteOracleSql} onNotify={addToast} onLogout={() => void telemetry.logout()}
      />

      <PdfExportModal
        isOpen={pdfExportOpen} onClose={() => setPdfExportOpen(false)} initialScope={pdfExportScope} metrics={metrics} users={telemetry.users} alerts={telemetry.alerts}
        auditLogs={telemetry.auditLogs} fgaEvents={telemetry.fgaEvents} triggers={telemetry.triggers} defaultPrivacyMode={privacyMode}
        onExportSuccess={(filename, pageCount, scope) => {
          const label = scope === 'alerts' ? 'Báo cáo Cảnh báo IDS' : scope === 'audit' ? 'Nhật ký Kiểm toán Audit Log' : 'Hồ sơ Bảo mật Tổng hợp SOC';
          addToast(`Đã xuất thành công ${label} (${pageCount} trang A4) -> ${filename}!`, 'success');
        }}
      />

      <Toast toasts={toasts} onDismiss={removeToast} />
    </div>
  );
}
