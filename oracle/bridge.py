import json
import os
import re
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import oracledb
import urllib.request

try:
    oracle_bin = r"D:\oracle\26ai\dbhomeFree\bin"
    if os.path.exists(oracle_bin):
        oracledb.init_oracle_client(lib_dir=oracle_bin)
    else:
        oracledb.init_oracle_client()
except Exception:
    pass

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ================= CẤU HÌNH KẾT NỐI ORACLE =================
DB_USER = "sys"
DB_PASS = "123456"  # Thay bằng mật khẩu SYS của bạn
DB_DSN = "localhost:1521/FREEPDB1"  # Đổi thành XEPDB1 nếu dùng bản XE
PORT = 8050

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ids_state.json")

# Trạng thái cấu hình IPS & Lịch sử xóa cảnh báo
APP_STATE = {
    "auto_response": True,
    # Mốc thời gian xóa toàn bộ cảnh báo IDS (chuỗi 'YYYY-MM-DD HH24:MI:SS')
    "alerts_cleared_at": "",
    "fga_cleared_at": "",
    "audit_cleared_at": "",
    # Mốc thời gian xác nhận/mở khóa/khôi phục quyền riêng cho từng User để không bị khóa/hạ quyền lại bởi cảnh báo cũ
    "user_cleared_at": {},
    # Tập hợp các cảnh báo đơn lẻ đã bấm xóa
    "dismissed_keys": set(),
    "dismissed_fga_keys": set(),
    "dismissed_audit_keys": set(),
    # Lưu vết số lần thực thi V$SQL tại thời điểm xóa lịch sử (hỗ trợ bắt lệnh khi chạy nhầm trên SYS_FREEPDB1)
    "vsql_baseline": {},
    # Lịch sử cảnh báo bền vững (không bị mất khi tự động làm mới 5s, chỉ xóa khi bấm Reset)
    "alert_history": {},
}


def load_persisted_state():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            APP_STATE["auto_response"] = bool(raw.get("auto_response", True))
            APP_STATE["alerts_cleared_at"] = str(raw.get("alerts_cleared_at", ""))
            APP_STATE["fga_cleared_at"] = str(raw.get("fga_cleared_at", ""))
            APP_STATE["audit_cleared_at"] = str(raw.get("audit_cleared_at", ""))
            APP_STATE["user_cleared_at"] = dict(raw.get("user_cleared_at", {}))
            APP_STATE["dismissed_keys"] = set(raw.get("dismissed_keys", []))
            APP_STATE["dismissed_fga_keys"] = set(raw.get("dismissed_fga_keys", []))
            APP_STATE["dismissed_audit_keys"] = set(raw.get("dismissed_audit_keys", []))
            APP_STATE["vsql_baseline"] = dict(raw.get("vsql_baseline", {}))
            APP_STATE["alert_history"] = dict(raw.get("alert_history", {}))
    except Exception:
        pass


def save_persisted_state():
    try:
        dismissed_list = list(APP_STATE["dismissed_keys"])[-500:]
        dismissed_fga_list = list(APP_STATE.get("dismissed_fga_keys", set()))[-500:]
        dismissed_audit_list = list(APP_STATE.get("dismissed_audit_keys", set()))[-500:]
        payload = {
            "auto_response": APP_STATE["auto_response"],
            "alerts_cleared_at": APP_STATE["alerts_cleared_at"],
            "fga_cleared_at": APP_STATE.get("fga_cleared_at", ""),
            "audit_cleared_at": APP_STATE.get("audit_cleared_at", ""),
            "user_cleared_at": APP_STATE["user_cleared_at"],
            "dismissed_keys": dismissed_list,
            "dismissed_fga_keys": dismissed_fga_list,
            "dismissed_audit_keys": dismissed_audit_list,
            "vsql_baseline": APP_STATE.get("vsql_baseline", {}),
            "alert_history": APP_STATE.get("alert_history", {}),
        }
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


load_persisted_state()


def get_connection():
    try:
        conn = oracledb.connect(mode=oracledb.AUTH_MODE_SYSDBA)
        cur = conn.cursor()
        cur.execute("ALTER SESSION SET CONTAINER = FREEPDB1")
        cur.close()
        return conn
    except Exception:
        pass
    return oracledb.connect(
        user=DB_USER,
        password=DB_PASS,
        dsn=DB_DSN,
        mode=oracledb.AUTH_MODE_SYSDBA,
    )


def get_oracle_now_str(cur):
    """Lấy thời gian hiện tại của Oracle Server theo định dạng chuẩn để so sánh."""
    cur.execute("SELECT TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD HH24:MI:SS') FROM DUAL")
    return cur.fetchone()[0]


def ensure_utf8_database_objects():
    """
    Đảm bảo toàn bộ cấu trúc Defense-in-Depth trên Oracle 23ai sẵn sàng:
    1. Đảm bảo các User thực nghiệm U1, U2, U3, U4 tồn tại
    2. Khôi phục dữ liệu chuẩn bảng SYS.NV (bao gồm NV1..NV4 và bẫy Honeytoken NV_TRAP) trước khi bật Trigger
    3. Trigger SYS.TRG_PROTECT_NV chặn trên mọi kết nối (kể cả khi chạy nhầm trên SYS_FREEPDB1)
    4. Hai chính sách DBMS_FGA: FGA_HONEYTOKEN_TRAP và FGA_HIGH_SALARY_ACCESS
    5. Unified Audit Policies: ids_logon_pol, ids_ddl_pol, ids_dml_nv_pol, ids_priv_abuse_pol
    """
    try:
        conn = get_connection()
        cur = conn.cursor()

        # 0. Đảm bảo các User U1, U2, U3, U4 tồn tại
        for uname, upass in (("U1", "U1123"), ("U2", "U2123"), ("U3", "U3123"), ("U4", "U4123")):
            try:
                cur.execute("SELECT COUNT(*) FROM dba_users WHERE username = :u", u=uname)
                if cur.fetchone()[0] == 0:
                    cur.execute(f"CREATE USER {uname} IDENTIFIED BY {upass}")
                cur.execute(f"GRANT CREATE SESSION, CREATE TABLE, UNLIMITED TABLESPACE TO {uname}")
            except Exception:
                pass

        # Tạm tắt Trigger nếu đang tồn tại để khôi phục dữ liệu gốc của bảng NV (nếu trước đó bị sửa/xóa nhầm)
        try:
            cur.execute("ALTER TRIGGER SYS.TRG_PROTECT_NV DISABLE")
        except Exception:
            pass

        # 1. Đảm bảo các bản ghi chuẩn (NV1..NV4) và bản ghi bẫy Honeytoken (NV_TRAP) đầy đủ, đúng chuẩn UTF-8
        default_nv_rows = [
            ("NV1", "Nguyen Van A", 900, "Nam", "001206012345"),
            ("NV2", "Tran Thi B", 850, "Nu", "001206099999"),
            ("NV3", "Le Van C", 1200, "Nam", "001206088888"),
            ("NV4", "Pham Thi D", 950, "Nu", "001206534243"),
            ("NV_TRAP", "Hoang Van Sếp (VIP)", 99999, "Nam", "001099000000"),
        ]
        for manv, hoten, luong, gioitinh, cmnd in default_nv_rows:
            try:
                cur.execute("SELECT COUNT(*) FROM SYS.NV WHERE manv = :m", m=manv)
                if cur.fetchone()[0] == 0:
                    cur.execute(
                        "INSERT INTO SYS.NV (manv, hoten, luong, gioitinh, cmnd) VALUES (:m, :h, :l, :g, :c)",
                        m=manv,
                        h=hoten,
                        l=luong,
                        g=gioitinh,
                        c=cmnd,
                    )
                else:
                    cur.execute(
                        "UPDATE SYS.NV SET hoten = :h, luong = :l, gioitinh = :g, cmnd = :c WHERE manv = :m",
                        h=hoten,
                        l=luong,
                        g=gioitinh,
                        c=cmnd,
                        m=manv,
                    )
            except Exception:
                pass

        # 2. Biên dịch lại Trigger chuẩn UTF-8 (chỉ áp dụng bảo vệ với các User nghiệp vụ, cho phép DBA SYS/SYSTEM khởi tạo dữ liệu)
        trigger_sql = """
        CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV
        BEFORE UPDATE OR DELETE ON SYSTEM.NV
        FOR EACH ROW
        DECLARE
            PRAGMA AUTONOMOUS_TRANSACTION;
            v_user VARCHAR2(50);
        BEGIN
            v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');
            IF v_user IN ('SYS', 'SYSTEM') THEN
                RETURN;
            END IF;

            IF DELETING THEN
                INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
                VALUES (v_user, 'UNAUTHORIZED_DELETE', 'Cố tình xóa nhân viên mã: ' || :OLD.manv);
                COMMIT;
                RAISE_APPLICATION_ERROR(-20001, 'IDS BLOCK: Ban khong duoc phep xoa du lieu nhan vien!');
            END IF;

            IF UPDATING('LUONG') AND :NEW.luong > :OLD.luong * 1.5 THEN
                INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
                VALUES (v_user, 'ABNORMAL_SALARY_MODIFICATION', 'Tăng lương bất thường từ ' || :OLD.luong || ' lên ' || :NEW.luong);
                COMMIT;
                RAISE_APPLICATION_ERROR(-20002, 'IDS BLOCK: Phat hien hanh vi gian lan tang luong vuot nguong!');
            END IF;
        END;
        """
        try:
            cur.execute(trigger_sql)
        except Exception:
            pass

        # 3. Khôi phục tiếng Việt cho các dòng log cũ bị lỗi dấu '?' trong SYS.IDS_TRIGGER_ALERTS
        try:
            cur.execute("SELECT alert_id, attack_type, details FROM SYS.IDS_TRIGGER_ALERTS WHERE details LIKE '%?%'")
            corrupted_rows = cur.fetchall()
            for alert_id, attack_type, details in corrupted_rows:
                fixed = str(details or "")
                if attack_type == "UNAUTHORIZED_DELETE":
                    m = re.search(r":\s*(.+)$", fixed)
                    manv = m.group(1).strip() if m else ""
                    fixed = f"Cố tình xóa nhân viên mã: {manv}"
                elif attack_type == "ABNORMAL_SALARY_MODIFICATION":
                    nums = re.findall(r"\d+(?:\.\d+)?", fixed)
                    if len(nums) >= 2:
                        fixed = f"Tăng lương bất thường từ {nums[0]} lên {nums[1]}"
                cur.execute(
                    "UPDATE SYS.IDS_TRIGGER_ALERTS SET details = :d WHERE alert_id = :id",
                    d=fixed,
                    id=alert_id,
                )
        except Exception:
            pass

        # 4. Đảm bảo 2 chính sách DBMS_FGA trên bảng NV được bật (kèm Handler chặn tức thời ORA-20003 cho Honeytoken)
        try:
            cur.execute(
                """
                CREATE OR REPLACE PROCEDURE SYS.IDS_FGA_TRAP_HANDLER(
                    object_schema VARCHAR2,
                    object_name   VARCHAR2,
                    policy_name   VARCHAR2
                ) AS
                    PRAGMA AUTONOMOUS_TRANSACTION;
                    v_user VARCHAR2(100) := SYS_CONTEXT('USERENV', 'SESSION_USER');
                    v_sql  VARCHAR2(4000) := SUBSTR(SYS_CONTEXT('USERENV', 'CURRENT_SQL'), 1, 2000);
                    v_type VARCHAR2(100) := 'HONEYTOKEN_TRAP_BLOCK';
                BEGIN
                    IF v_user IN ('SYS', 'SYSTEM') THEN
                        RETURN;
                    END IF;
                    IF REGEXP_LIKE(v_sql, '\\b(COUNT|SUM|AVG|STDDEV|VARIANCE)\\s*\\(', 'i')
                       AND NOT REGEXP_LIKE(v_sql, 'NV_TRAP', 'i')
                       AND NOT REGEXP_LIKE(v_sql, '(\\bOR\\b\\s+1\\s*=\\s*1|\\bUNION\\b\\s+\\bSELECT\\b|--)', 'i') THEN
                        RETURN;
                    END IF;
                    IF REGEXP_LIKE(v_sql, '(\\bOR\\b\\s+1\\s*=\\s*1|\\bOR\\b\\s+''1''\\s*=\\s*''1''|\\bUNION\\b\\s+\\bSELECT\\b)', 'i') THEN
                        v_type := 'SQL_INJECTION_BLOCK';
                    END IF;
                    INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
                    VALUES (
                        v_user,
                        v_type,
                        NVL(v_sql, 'SELECT * FROM SYS.NV WHERE manv = ''NV_TRAP''')
                    );
                    COMMIT;
                    RAISE_APPLICATION_ERROR(-20003, 'IDS ACTIVE BLOCK (ORA-20003): Phat hien hanh vi doc trom du lieu nhay cam / SQL Injection cham bay Honeytoken NV_TRAP! Truy van SELECT bi tu choi tuc thoi!');
                END;
                """
            )
        except Exception:
            pass

        try:
            cur.execute(
                "SELECT policy_name, handler_module FROM dba_audit_policies "
                "WHERE object_name = 'NV' AND policy_name IN ('FGA_HONEYTOKEN_TRAP', 'FGA_HIGH_SALARY_ACCESS')"
            )
            existing_fga_rows = cur.fetchall()
            existing_fga = {r[0]: r[1] for r in existing_fga_rows}
            # Xác định schema vật lý của bảng NV (SYSTEM hoặc SYS)
            cur.execute(
                "SELECT owner FROM dba_tables WHERE table_name = 'NV' AND owner IN ('SYSTEM', 'SYS') ORDER BY DECODE(owner, 'SYSTEM', 1, 2)"
            )
            row_owner = cur.fetchone()
            target_schema = row_owner[0] if row_owner else "SYSTEM"

            if existing_fga.get("FGA_HONEYTOKEN_TRAP") != "IDS_FGA_TRAP_HANDLER":
                if "FGA_HONEYTOKEN_TRAP" in existing_fga:
                    try:
                        cur.execute(
                            "BEGIN DBMS_FGA.DROP_POLICY(object_schema => :sch, object_name => 'NV', policy_name => 'FGA_HONEYTOKEN_TRAP'); END;",
                            sch=target_schema,
                        )
                    except Exception:
                        pass
                cur.execute(
                    """
                    BEGIN
                        DBMS_FGA.ADD_POLICY(
                            object_schema   => :sch,
                            object_name     => 'NV',
                            policy_name     => 'FGA_HONEYTOKEN_TRAP',
                            audit_condition => 'manv = ''NV_TRAP''',
                            audit_column    => NULL,
                            handler_schema  => 'SYS',
                            handler_module  => 'IDS_FGA_TRAP_HANDLER',
                            statement_types => 'SELECT, UPDATE, DELETE',
                            enable          => TRUE
                        );
                    END;
                    """,
                    sch=target_schema,
                )
            if "FGA_HIGH_SALARY_ACCESS" not in existing_fga:
                cur.execute(
                    """
                    BEGIN
                        DBMS_FGA.ADD_POLICY(
                            object_schema   => :sch,
                            object_name     => 'NV',
                            policy_name     => 'FGA_HIGH_SALARY_ACCESS',
                            audit_condition => 'luong >= 1000',
                            audit_column    => 'LUONG, CMND',
                            statement_types => 'SELECT, UPDATE, DELETE',
                            enable          => TRUE
                        );
                    END;
                    """,
                    sch=target_schema,
                )
        except Exception:
            pass

        # 5. Đảm bảo Unified Audit Policy ids_priv_abuse_pol được tạo và kích hoạt
        try:
            cur.execute(
                "CREATE AUDIT POLICY ids_priv_abuse_pol ACTIONS GRANT, REVOKE, CREATE USER, ALTER USER, DROP USER"
            )
        except Exception:
            pass
        try:
            cur.execute("AUDIT POLICY ids_priv_abuse_pol")
        except Exception:
            pass

        # 6. Tự động đồng bộ quyền & Audit Policy cho mọi User thực nghiệm (U1, U2, U3, ...)
        try:
            cur.execute(
                "SELECT username FROM dba_users WHERE oracle_maintained = 'N' AND username NOT IN ('PDBADMIN')"
            )
            monitored_users = [r[0] for r in cur.fetchall()]
            for u in monitored_users:
                cur.execute(
                    "SELECT COUNT(*) FROM dba_tab_privs WHERE grantee = :u AND table_name = 'NV'",
                    u=u,
                )
                if cur.fetchone()[0] == 0:
                    try:
                        cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO {u}")
                    except Exception:
                        pass
                for pol in ("ids_ddl_pol", "ids_dml_nv_pol"):
                    try:
                        cur.execute(f"AUDIT POLICY {pol} BY {u}")
                    except Exception:
                        pass
        except Exception:
            pass

        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass


def flush_audit_trail(cur):
    """Đẩy dữ liệu audit từ bộ nhớ xuống bảng (tương thích cả Oracle 19c/21c và 23ai)."""
    for stmt in (
        "BEGIN DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;",
        "BEGIN AUDSYS.DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;",
        "BEGIN SYS.DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL; END;",
    ):
        try:
            cur.execute(stmt)
            return
        except Exception:
            pass


# ================= CÁC HÀM PHẢN ỨNG ĐA CẤP (GRADUATED ACTIVE RESPONSE) =================
def lock_user(username):
    """Level 3 - Full Isolation: Khóa tài khoản và Kill toàn bộ phiên đang kết nối."""
    username = str(username or "").strip().upper()
    if not re.match(r"^[A-Z0-9_#$]+$", username):
        return False, "Tên tài khoản không hợp lệ!"
    if username in ["SYS", "SYSTEM"]:
        return False, "Không thể khóa tài khoản quản trị hệ thống!"
    try:
        conn = get_connection()
        cur = conn.cursor()
        # 1. Khóa tài khoản
        cur.execute(f"ALTER USER {username} ACCOUNT LOCK")
        # 2. Ngắt toàn bộ phiên đang kết nối của user đó
        cur.execute(
            "SELECT sid, serial# FROM v$session WHERE username = :u",
            u=username,
        )
        for sid, serial in cur.fetchall():
            try:
                cur.execute(f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE")
            except Exception:
                pass
        conn.commit()
        cur.close()
        conn.close()
        return True, f"[Level 3 - Full Isolation] Đã KHÓA tài khoản {username} và ngắt tức thời các phiên kết nối!"
    except Exception as e:
        return False, str(e)


def unlock_user(username):
    """Mở khóa tài khoản và đặt lại mốc thời gian an toàn cho User."""
    username = str(username or "").strip().upper()
    if not re.match(r"^[A-Z0-9_#$]+$", username):
        return False, "Tên tài khoản không hợp lệ!"
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(f"ALTER USER {username} ACCOUNT UNLOCK")
        # Ghi nhận mốc thời gian mở khóa để các cảnh báo cũ trước thời điểm này không tự khóa lại User
        now_str = get_oracle_now_str(cur)
        APP_STATE["user_cleared_at"][username] = now_str
        save_persisted_state()
        conn.commit()
        cur.close()
        conn.close()
        return True, f"Đã MỞ KHÓA tài khoản {username} và đặt lại điểm rủi ro (Risk Score = 0)!"
    except Exception as e:
        return False, str(e)


def revoke_dml_user(username):
    """
    Level 2 - Privilege Containment (Hạ quyền tạm thời):
    Thực thi REVOKE INSERT, UPDATE, DELETE ON SYS.NV FROM <user> để chuyển về chế độ Read-Only.
    """
    username = str(username or "").strip().upper()
    if not re.match(r"^[A-Z0-9_#$]+$", username):
        return False, "Tên tài khoản không hợp lệ!"
    if username in ["SYS", "SYSTEM"]:
        return False, "Không thể thu hồi quyền của tài khoản quản trị hệ thống!"
    try:
        conn = get_connection()
        cur = conn.cursor()
        revoked_any = False
        try:
            cur.execute(f"REVOKE INSERT, UPDATE, DELETE ON SYS.NV FROM {username}")
            revoked_any = True
        except Exception:
            for priv in ("INSERT", "UPDATE", "DELETE"):
                try:
                    cur.execute(f"REVOKE {priv} ON SYS.NV FROM {username}")
                    revoked_any = True
                except Exception:
                    pass
        # Đảm bảo user vẫn còn quyền SELECT để đọc ở chế độ Read-Only
        try:
            cur.execute(f"GRANT SELECT ON SYS.NV TO {username}")
        except Exception:
            pass
        conn.commit()
        cur.close()
        conn.close()
        if revoked_any:
            return (
                True,
                f"[Level 2 - Privilege Containment] Đã thu hồi quyền DML (INSERT, UPDATE, DELETE) của {username} -> Chuyển về chế độ Read-Only!",
            )
        return True, f"Tài khoản {username} hiện đã ở chế độ Read-Only (chỉ có quyền SELECT)!"
    except Exception as e:
        return False, str(e)


def grant_dml_user(username):
    """
    Khôi phục quyền DML đầy đủ (SELECT, INSERT, UPDATE, DELETE) trên bảng SYS.NV cho User
    và đặt lại mốc thời gian cảnh báo của User đó.
    """
    username = str(username or "").strip().upper()
    if not re.match(r"^[A-Z0-9_#$]+$", username):
        return False, "Tên tài khoản không hợp lệ!"
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO {username}")
        now_str = get_oracle_now_str(cur)
        APP_STATE["user_cleared_at"][username] = now_str
        save_persisted_state()
        conn.commit()
        cur.close()
        conn.close()
        return (
            True,
            f"Đã KHÔI PHỤC toàn bộ quyền DML (SELECT, INSERT, UPDATE, DELETE) trên SYS.NV cho {username}!",
        )
    except Exception as e:
        return False, str(e)


def clear_alert_history(
    target="all",
    alert_id=None,
    alert_key=None,
    reviewed_keys=None,
    reviewed_fga_keys=None,
    reviewed_trigger_ids=None,
    reviewed_audit_keys=None,
):
    """
    Xóa lịch sử cảnh báo:
    - target == 'ids': Xóa các cảnh báo phân tích từ Audit Log (đặt mốc thời gian mới)
    - target == 'triggers': Xóa toàn bộ bản ghi trong SYS.IDS_TRIGGER_ALERTS
    - target == 'fga': Xóa lịch sử sự kiện FGA (đặt mốc fga_cleared_at)
    - target == 'audit': Xóa lịch sử Unified Audit Trail (đặt mốc audit_cleared_at & dọn bộ nhớ Oracle)
    - target == 'reviewed': Xóa vĩnh viễn các mục đã kiểm duyệt khỏi bộ nhớ
    - target == 'all': Xóa toàn bộ + tự động mở khóa và khôi phục quyền FULL DML cho các User thực nghiệm
    - target == 'single_trigger': Xóa 1 dòng trong SYS.IDS_TRIGGER_ALERTS theo alert_id
    - target == 'single_ids': Xóa 1 dòng cảnh báo IDS theo alert_key
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        now_str = get_oracle_now_str(cur)

        if target == "single_ids" and alert_key:
            APP_STATE["dismissed_keys"].add(str(alert_key))
            if "alert_history" in APP_STATE and str(alert_key) in APP_STATE["alert_history"]:
                del APP_STATE["alert_history"][str(alert_key)]
            save_persisted_state()
            cur.close()
            conn.close()
            return True, "Đã xóa cảnh báo khỏi danh sách!"

        if target == "single_trigger" and alert_id is not None:
            cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS WHERE alert_id = :id", id=int(alert_id))
            conn.commit()
            cur.close()
            conn.close()
            return True, f"Đã xóa bản ghi Trigger #{alert_id}!"

        if target == "reviewed":
            for k in (reviewed_keys or []):
                ks = str(k)
                APP_STATE["dismissed_keys"].add(ks)
                APP_STATE.get("alert_history", {}).pop(ks, None)
            for fk in (reviewed_fga_keys or []):
                APP_STATE.setdefault("dismissed_fga_keys", set()).add(str(fk))
            for ak in (reviewed_audit_keys or []):
                APP_STATE.setdefault("dismissed_audit_keys", set()).add(str(ak))
            for tid in (reviewed_trigger_ids or []):
                try:
                    cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS WHERE alert_id = :id", id=int(tid))
                except Exception:
                    pass
            conn.commit()
            # Nếu toàn bộ cảnh báo đã được duyệt và xóa hết, cập nhật mốc thời gian và giải phóng bộ nhớ Audit Trail
            remaining_active = [
                k for k in APP_STATE.get("alert_history", {}) if k not in APP_STATE["dismissed_keys"]
            ]
            if not remaining_active and reviewed_keys:
                APP_STATE["alerts_cleared_at"] = now_str
                APP_STATE["alert_history"] = {}
                APP_STATE["dismissed_keys"].clear()
                try:
                    cur.execute(
                        """
                        BEGIN
                            DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(
                                audit_trail_type => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
                                use_last_arch_timestamp => FALSE
                            );
                        END;
                        """
                    )
                except Exception:
                    pass
            save_persisted_state()
            cur.close()
            conn.close()
            return True, "Đã xóa vĩnh viễn các cảnh báo đã kiểm duyệt khỏi bộ nhớ!"

        if target == "fga":
            APP_STATE["fga_cleared_at"] = now_str
            APP_STATE.setdefault("dismissed_fga_keys", set()).clear()
            save_persisted_state()
            cur.close()
            conn.close()
            return True, "Đã xóa lịch sử sự kiện FGA!"

        if target == "audit":
            APP_STATE["audit_cleared_at"] = now_str
            APP_STATE.setdefault("dismissed_audit_keys", set()).clear()
            save_persisted_state()
            try:
                cur.execute(
                    """
                    BEGIN
                        DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(
                            audit_trail_type => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
                            use_last_arch_timestamp => FALSE
                        );
                    END;
                    """
                )
            except Exception:
                pass
            conn.commit()
            cur.close()
            conn.close()
            return True, "Đã xóa nhật ký Unified Audit Trail và giải phóng bộ nhớ!"

        if target in ("ids", "all"):
            APP_STATE["alerts_cleared_at"] = now_str
            if target == "all":
                APP_STATE["fga_cleared_at"] = now_str
                APP_STATE["audit_cleared_at"] = now_str
                APP_STATE.setdefault("dismissed_fga_keys", set()).clear()
                APP_STATE.setdefault("dismissed_audit_keys", set()).clear()
            APP_STATE["dismissed_keys"].clear()
            APP_STATE["alert_history"] = {}
            try:
                cur.execute(
                    "SELECT username FROM dba_users WHERE oracle_maintained = 'N' AND username NOT IN ('PDBADMIN')"
                )
                exp_users = [r[0] for r in cur.fetchall()]
            except Exception:
                exp_users = ["U1", "U2", "U3", "U4"]

            for u_name in exp_users:
                APP_STATE["user_cleared_at"][u_name] = now_str
                if re.match(r"^[A-Z0-9_#$]+$", str(u_name)):
                    try:
                        cur.execute(f"ALTER USER {u_name} ACCOUNT UNLOCK")
                    except Exception:
                        pass
                    try:
                        cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO {u_name}")
                    except Exception:
                        pass

            save_persisted_state()
            try:
                cur.execute(
                    """
                    BEGIN
                        DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(
                            audit_trail_type => DBMS_AUDIT_MGMT.AUDIT_TRAIL_UNIFIED,
                            use_last_arch_timestamp => FALSE
                        );
                    END;
                    """
                )
            except Exception:
                pass

        if target in ("triggers", "all"):
            cur.execute("DELETE FROM SYS.IDS_TRIGGER_ALERTS")
            conn.commit()

        # Khôi phục dữ liệu chuẩn bảng SYS.NV (bao gồm cả NV_TRAP)
        try:
            cur.execute(
                """
                MERGE INTO SYSTEM.NV t USING (
                    SELECT 'NV1' m, 'Nguyen Van A' h, 900 l, 'Nam' g, '001206012345' c FROM DUAL UNION ALL
                    SELECT 'NV2', 'Tran Thi B', 850, 'Nu', '001206099999' FROM DUAL UNION ALL
                    SELECT 'NV3', 'Le Van C', 1200, 'Nam', '001206088888' FROM DUAL UNION ALL
                    SELECT 'NV4', 'Pham Thi D', 950, 'Nu', '001206534243' FROM DUAL UNION ALL
                    SELECT 'NV_TRAP', 'Hoang Van S\u1ebfp (VIP)', 99999, 'Nam', '001099000000' FROM DUAL
                ) s ON (t.manv = s.m)
                WHEN MATCHED THEN
                    UPDATE SET t.hoten = s.h, t.luong = s.l, t.gioitinh = s.g, t.cmnd = s.c
                WHEN NOT MATCHED THEN
                    INSERT (manv, hoten, luong, gioitinh, cmnd) VALUES (s.m, s.h, s.l, s.g, s.c)
                """
            )
            conn.commit()
        except Exception:
            pass

        conn.commit()
        cur.close()
        conn.close()
        if target == "ids":
            return True, "Đã xóa lịch sử cảnh báo IDS, đặt lại Risk Score = 0 & khôi phục quyền User!"
        if target == "triggers":
            return True, "Đã xóa toàn bộ lịch sử cảnh báo Trigger!"
        return True, "Đã xóa toàn bộ lịch sử cảnh báo IDS, FGA, Trigger & khôi phục trạng thái User!"
    except Exception as e:
        return False, str(e)


# ================= BỘ PHÂN TÍCH PHÁT HIỆN XÂM NHẬP ĐA CHIỀU (DETECTION ENGINE) =================
SQLI_PATTERNS = re.compile(
    r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|\bOR\b\s+['\"][a-zA-Z0-9]+['\"]\s*=\s*['\"][a-zA-Z0-9]+['\"]|\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|--|/\*|\bDBMS_PIPE\b|\bUTL_HTTP\b|\bUTL_INADDR\b)",
    re.IGNORECASE,
)

HONEYTOKEN_PATTERNS = re.compile(r"(NV_TRAP|001099000000)", re.IGNORECASE)

STAT_FUNC_PATTERNS = re.compile(r"\b(COUNT|SUM|AVG|MAX|MIN)\s*\(", re.IGNORECASE)
WHERE_CLAUSE_PATTERN = re.compile(r"\bWHERE\b\s+(.+)$", re.IGNORECASE | re.DOTALL)

PRIV_ABUSE_ACTIONS = {
    "GRANT",
    "REVOKE",
    "CREATE USER",
    "ALTER USER",
    "DROP USER",
    "ALTER SYSTEM",
    "ALTER DATABASE",
    "AUDIT",
    "NOAUDIT",
}

DDL_DANGEROUS_ACTIONS = {"DROP TABLE", "TRUNCATE TABLE", "ALTER TABLE", "CREATE TABLE"}

SUSPICIOUS_CLIENTS = re.compile(
    r"(sqlmap|hydra|nikto|burp|nmap|nc|netcat|curl|wget|powershell|pwsh|cmd\.exe|metasploit)",
    re.IGNORECASE,
)

CRYPTO_KEY_DIRECT_PATTERNS = re.compile(
    r"\b(V\$ENCRYPTION_KEYS|V\$ENCRYPTION_WALLET|DBA_ENCRYPTED_COLUMNS|ENC\$|USER_ENCRYPTED_COLUMNS)\b",
    re.IGNORECASE,
)

CRYPTO_KEY_INDIRECT_PATTERNS = re.compile(
    r"\b(DBMS_CRYPTO|ADMINISTER\s+KEY\s+MANAGEMENT|UTL_I18N\.STRING_TO_RAW)\b",
    re.IGNORECASE,
)

MASQUERADE_HOSTS = re.compile(
    r"(kali|parrot|attacker|rogue|unknown|tor-exit|vpn-ext)",
    re.IGNORECASE,
)


def classify_response_level(score):
    """
    Ánh xạ Risk Score (0-100) sang cấp độ phản ứng (Graduated Active Response):
    - Level 0 (0 - 19)  : Normal (An toàn)
    - Level 1 (20 - 49) : LOW / MEDIUM -> Warning & Session Monitoring
    - Level 2 (50 - 79) : HIGH -> Privilege Containment (REVOKE DML -> Read-Only)
    - Level 3 (80 - 100): CRITICAL -> Full Isolation (ACCOUNT LOCK + KILL SESSION)
    """
    score = int(max(0, min(100, score)))
    if score >= 80:
        return 3, "Level 3: CRITICAL (Full Isolation)"
    if score >= 50:
        return 2, "Level 2: HIGH (Privilege Containment)"
    if score >= 20:
        return 1, "Level 1: LOW/MED (Warning & Monitor)"
    return 0, "Level 0: Normal (An toàn)"


def is_event_cleared(user, event_time):
    """Kiểm tra xem sự kiện ở thời điểm event_time đã được xóa lịch sử toàn cục chưa."""
    if not event_time:
        return False
    global_cut = APP_STATE.get("alerts_cleared_at") or ""
    if global_cut and event_time <= global_cut:
        return True
    return False


def is_event_active_for_user_risk(user, event_time):
    """
    Kiểm tra xem sự kiện có được tính vào Risk Score hiện tại của User hay không
    (mới hơn cả mốc xóa toàn cục lẫn mốc Mở khóa / Khôi phục quyền DML của User đó).
    """
    if not user or not event_time:
        return False
    user_cut = APP_STATE["user_cleared_at"].get(user, "")
    global_cut = APP_STATE.get("alerts_cleared_at") or ""
    cutoff = max(user_cut, global_cut)
    if cutoff and event_time <= cutoff:
        return False
    return True


def format_context_str(row):
    prog = str(row.get("CLIENT_PROGRAM_NAME") or "").strip() or "Unknown Client"
    host = str(row.get("USERHOST") or "").strip() or "Unknown Host"
    os_user = str(row.get("OS_USERNAME") or "").strip()
    if os_user:
        return f"{prog} ({os_user}@{host})"
    return f"{prog} ({host})"


def make_alert_item(key, severity, risk_score, event_time, user, attack_type, details, row=None):
    row = row or {}
    lvl_num, lvl_label = classify_response_level(risk_score)
    return {
        "key": key,
        "severity": severity,
        "risk_score": int(risk_score),
        "response_level": lvl_num,
        "response_label": lvl_label,
        "time": event_time,
        "user": user,
        "attack_type": attack_type,
        "details": details,
        "client_program": str(row.get("CLIENT_PROGRAM_NAME") or "—"),
        "userhost": str(row.get("USERHOST") or "—"),
        "os_username": str(row.get("OS_USERNAME") or "—"),
        "fga_policy": str(row.get("FGA_POLICY_NAME") or ""),
        "audit_type": str(row.get("AUDIT_TYPE") or "Standard"),
        "context": format_context_str(row) if row else "Oracle Session",
    }


def analyze_audit_logs(audit_rows, failed_rows, trig_rows, user_info_map, auto_block=False):
    """
    Bộ phân tích đa chiều (Defense-in-Depth Detection Engine):
    0. Vi phạm bị chặn bởi Database Trigger (ABNORMAL_SALARY_MODIFICATION, UNAUTHORIZED_DELETE)
    1. Signature-based & FGA Trap Detection:
       - Tấn công trực tiếp (Direct Attack) & Honeytoken NV_TRAP
       - SQL Injection
       - Truy cập khóa mã hóa trái phép (Trực tiếp vào V$ENCRYPTION_KEYS/WALLET & Gián tiếp qua DBMS_CRYPTO)
       - Giả mạo / Giả danh (Masquerading Attack)
       - Leo thang đặc quyền (Privilege Escalation) & DDL trái phép
       - Tấn công đăng nhập thất bại (Failed Logins / Brute-Force ORA-01017)
    2. Vi phạm Read-Only / Thao tác DML khi bị hạ quyền (ORA-41900 / ORA-01031)
    3. Các kiểu tấn công Suy diễn vào CSDL Thống kê (SDB):
       - Tấn công dựa vào đếm (Count-based Attack: COUNT=1 kết hợp SUM)
       - Tấn công trình theo dõi (Tracker Attack: lách Query-Set-Size Control)
       - Tấn công hệ tuyến tính (Linear System Attack: giải hệ A*X = B từ chuỗi SUM)
    4. Chấm điểm rủi ro (Risk Score 0-100) cho từng User & Kích hoạt phản ứng đa cấp (Level 1 / Level 2 / Level 3)
    """
    if "alert_history" not in APP_STATE:
        APP_STATE["alert_history"] = {}

    auto_locked = []
    auto_revoked = []

    monitored_set = set(user_info_map.keys()) | {"U1", "U2", "U3", "U4"}
    stat_queries_by_user = {u: [] for u in monitored_set}
    query_times_by_user = {u: [] for u in monitored_set}
    suspicious_client_by_user = {}

    # -------------------------------------------------------------------------
    # 0. Đưa các vi phạm bị chặn bởi Trigger nội sinh / FGA Handler (SYS.IDS_TRIGGER_ALERTS) vào kho cảnh báo
    # -------------------------------------------------------------------------
    for t_row in trig_rows:
        t_id = t_row.get("ALERT_ID")
        t_time = str(t_row.get("EVENT_TIME") or t_row.get("EVENT_TIMESTAMP") or "").strip()
        t_user = str(t_row.get("DB_USER") or "UNKNOWN").strip().upper()
        t_type = str(t_row.get("ATTACK_TYPE") or "TRIGGER_BLOCK").strip().upper()
        t_details = str(t_row.get("DETAILS") or "").strip()
        if is_event_cleared(t_user, t_time):
            continue
        alert_key = f"TRIG|{t_id}|{t_user}|{t_time}"
        if alert_key not in APP_STATE["dismissed_keys"]:
            if "HONEYTOKEN" in t_type or "FGA_HONEYTOKEN" in t_type:
                vn_label = "SDB Direct Attack & Honeytoken Trap (Chặn tức thời ORA-20003)"
                t_sev = "CRITICAL"
                t_score = 95
                t_row_meta = {
                    "CLIENT_PROGRAM_NAME": "FGA Handler Block (ORA-20003)",
                    "USERHOST": "SYS.IDS_FGA_TRAP_HANDLER",
                    "FGA_POLICY_NAME": "FGA_HONEYTOKEN_TRAP",
                    "AUDIT_TYPE": "FineGrainedAudit",
                }
            elif "SQL_INJECTION" in t_type or "SQLI" in t_type:
                vn_label = "SQL Injection Attack (Chặn tức thời ORA-20003)"
                t_sev = "CRITICAL"
                t_score = 95
                t_row_meta = {
                    "CLIENT_PROGRAM_NAME": "FGA Handler Block (ORA-20003)",
                    "USERHOST": "SYS.IDS_FGA_TRAP_HANDLER",
                    "FGA_POLICY_NAME": "FGA_HONEYTOKEN_TRAP",
                    "AUDIT_TYPE": "FineGrainedAudit",
                }
            elif "SALARY" in t_type:
                vn_label = "Trigger Block: Gian lận tăng lương > 50% (ORA-20002)"
                t_sev = "HIGH"
                t_score = 65
                t_row_meta = {"CLIENT_PROGRAM_NAME": "Database Trigger", "USERHOST": "SYS.TRG_PROTECT_NV"}
            else:
                vn_label = "Trigger Block: Xóa nhân viên trái phép (ORA-20001)"
                t_sev = "HIGH"
                t_score = 65
                t_row_meta = {"CLIENT_PROGRAM_NAME": "Database Trigger", "USERHOST": "SYS.TRG_PROTECT_NV"}

            item = make_alert_item(
                key=alert_key,
                severity=t_sev,
                risk_score=t_score,
                event_time=t_time,
                user=t_user,
                attack_type=vn_label,
                details=t_details,
                row=t_row_meta,
            )
            APP_STATE["alert_history"][alert_key] = item

    # -------------------------------------------------------------------------
    # 1. Phát hiện Tấn công đăng nhập thất bại / Brute-force Logon (ORA-01017 >= 3 lần) -> Level 3 (Score: 90)
    # -------------------------------------------------------------------------
    for row in failed_rows:
        fail_count = int(row.get("FAIL_COUNT") or 0)
        last_attempt = str(row.get("LAST_ATTEMPT") or "")
        user = str(row.get("DBUSERNAME") or "")
        if fail_count >= 3 and not is_event_cleared(user, last_attempt):
            alert_key = f"BF|{user}|{last_attempt}|{fail_count}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=90,
                    event_time=last_attempt,
                    user=user,
                    attack_type="Tấn công đăng nhập thất bại / Brute-Force Logon (ORA-01017)",
                    details=f"Dò quét mật khẩu / đăng nhập thất bại {fail_count} lần liên tiếp trong 15 phút qua",
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item

    # -------------------------------------------------------------------------
    # 2. Phân tích từng bản ghi trong UNIFIED_AUDIT_TRAIL
    # -------------------------------------------------------------------------
    for row in audit_rows:
        sql_text = str(row.get("SQL_TEXT") or "").strip()
        action = str(row.get("ACTION_NAME") or "").strip().upper()
        raw_user = str(row.get("DBUSERNAME") or "").strip().upper()
        if raw_user in ("SYS", "SYSTEM"):
            continue
        user = raw_user
        event_time = str(row.get("EVENT_TIMESTAMP") or "").strip()
        fga_policy = str(row.get("FGA_POLICY_NAME") or "").strip().upper()
        audit_type = str(row.get("AUDIT_TYPE") or "").strip()
        client_prog = str(row.get("CLIENT_PROGRAM_NAME") or "").strip()
        userhost = str(row.get("USERHOST") or "").strip()
        os_username = str(row.get("OS_USERNAME") or "").strip()
        return_code = int(row.get("RETURN_CODE") or 0)

        if "python" in client_prog.lower() and raw_user in ("SYS", "SYSTEM"):
            continue

        if not user or is_event_cleared(user, event_time):
            continue

        norm_sql = re.sub(r"\s+", " ", sql_text).upper()
        # Bỏ qua các câu lệnh tra cứu Dictionary nội bộ tự động của Oracle SQL Developer / JDBC
        if any(
            ide_kw in norm_sql
            for ide_kw in (
                "FROM ALL_OBJECTS",
                "FROM ALL_TAB_COLS",
                "FROM ALL_SYNONYMS",
                "FROM ALL_TABLES",
                "FROM ALL_VIEWS",
                "FROM ALL_USERS",
                "FROM ALL_PROCEDURES",
                "FROM ALL_ARGUMENTS",
                "FROM ALL_CONSTRAINTS",
                "FROM ALL_INDEXES",
                "FROM ALL_TRIGGERS",
                "FROM ALL_SOURCE",
                "_CURRENT_EDITION_OBJ",
                "NLS_SESSION_PARAMETERS",
                "DBMS_APPLICATION_INFO",
                "DBMS_OUTPUT.",
                "FROM DUAL",
                "FROM SYS.DUAL",
                "DATABASE_COMPATIBLE_LEVEL",
                "V$OPTION",
                "V$VERSION",
                "USER_ROLE_PRIVS",
                "USER_USERS",
                "DG_COUNT",
                "TAB_COUNT",
                "INST_COUNT",
                "SYS_CONTEXT('USERENV', 'CON_ID')",
                "SYS_CONTEXT('USERENV', 'SERVICE_NAME')",
            )
        ):
            continue

        is_stat_query = bool(
            action == "SELECT"
            and sql_text
            and STAT_FUNC_PATTERNS.search(sql_text)
            and not HONEYTOKEN_PATTERNS.search(sql_text)
        )

        # 2.1. Tấn công trực tiếp (Direct Attack) & Bẫy Honeytoken (FGA_HONEYTOKEN_TRAP hoặc chạm NV_TRAP) -> CRITICAL (Score: 95, Level 3)
        if (fga_policy == "FGA_HONEYTOKEN_TRAP" and not is_stat_query and not SQLI_PATTERNS.search(sql_text)) or HONEYTOKEN_PATTERNS.search(sql_text):
            alert_key = f"TRAP|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=95,
                    event_time=event_time,
                    user=user,
                    attack_type="SDB Direct Attack & Honeytoken Trap (Tấn công trực tiếp)",
                    details=sql_text or "Truy vấn trực tiếp dữ liệu cá nhân nhạy cảm chạm bẫy MANV = 'NV_TRAP'",
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item
            continue

        # 2.2. Phát hiện Truy cập khóa mã hóa trái phép (Trực tiếp & Gián tiếp) -> CRITICAL (Score: 92, Level 3)
        if sql_text and (CRYPTO_KEY_DIRECT_PATTERNS.search(sql_text) or CRYPTO_KEY_INDIRECT_PATTERNS.search(sql_text)):
            is_direct_key = bool(CRYPTO_KEY_DIRECT_PATTERNS.search(sql_text))
            sub_label = "Truy cập trực tiếp bảng/kho khóa TDE" if is_direct_key else "Truy cập gián tiếp qua DBMS_CRYPTO/ dịch vụ giải mã"
            alert_key = f"CRYPTO|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=92,
                    event_time=event_time,
                    user=user,
                    attack_type=f"Unauthorized Encryption Key Access ({sub_label})",
                    details=sql_text,
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item
            continue

        # 2.3. Phát hiện SQL Injection -> CRITICAL (Score: 95, Level 3)
        if sql_text and SQLI_PATTERNS.search(sql_text):
            alert_key = f"SQLI|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=95,
                    event_time=event_time,
                    user=user,
                    attack_type="SQL Injection Attack (Chèn mã độc SQL)",
                    details=sql_text,
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item
            continue

        # 2.4. Phát hiện Giả mạo / Giả danh (Masquerading Attack) -> HIGH (Score: 75, Level 2)
        if user in monitored_set and (MASQUERADE_HOSTS.search(userhost) or MASQUERADE_HOSTS.search(os_username)):
            alert_key = f"MASQ|{user}|{event_time[:16]}|{userhost}|{os_username}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=75,
                    event_time=event_time,
                    user=user,
                    attack_type="Masquerading Attack (Giả mạo / Giả danh tài khoản hợp pháp)",
                    details=f"Đăng nhập / Truy vấn bằng thông tin xác thực của {user} nhưng từ Host/OS bất thường ({os_username}@{userhost}, Client: {client_prog}): {sql_text or action}",
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item

        # 2.5. Phát hiện hành vi cố tình sửa lương / xóa nhân viên khi bị hạ quyền Read-Only (ORA-41900 / ORA-01031 / return_code = 2004)
        is_dml_statement = (
            action in ("UPDATE", "DELETE", "INSERT")
            or "UPDATE " in norm_sql
            or "DELETE FROM" in norm_sql
            or "INSERT INTO" in norm_sql
        )
        if is_dml_statement and return_code in (1031, 2004, 41900):
            if "DELETE" in norm_sql or action == "DELETE":
                dml_action_vn = "Xóa nhân viên (DELETE)"
            elif "UPDATE" in norm_sql or action == "UPDATE":
                dml_action_vn = "Sửa lương / Cập nhật dữ liệu (UPDATE)"
            elif "INSERT" in norm_sql or action == "INSERT":
                dml_action_vn = "Thêm nhân viên (INSERT)"
            else:
                dml_action_vn = action or "DML"

            err_code_str = f"ORA-{return_code}" if return_code in (1031, 41900) else "ORA-41900"
            alert_key = f"DML_RO|{user}|{event_time}|{norm_sql[:50]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=65,
                    event_time=event_time,
                    user=user,
                    attack_type=f"Vi phạm Read-Only (Hạ quyền Level 2): Cố tình {dml_action_vn} ({err_code_str})",
                    details=sql_text or f"Tài khoản đang ở chế độ Read-Only do vi phạm trước đó nhưng vẫn cố tình thực hiện thao tác {dml_action_vn}",
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item
            continue

        # 2.6. Kiểm toán mịn FGA: Truy cập trực tiếp cột nhạy cảm LUONG, CMND với luong >= 1000 -> MEDIUM (Score: 30, Level 1)
        if fga_policy == "FGA_HIGH_SALARY_ACCESS" and not STAT_FUNC_PATTERNS.search(sql_text):
            alert_key = f"FGA_SAL|{user}|{event_time}|{norm_sql[:60]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="MEDIUM",
                    risk_score=30,
                    event_time=event_time,
                    user=user,
                    attack_type="SDB Direct Attack (FGA_HIGH_SALARY_ACCESS)",
                    details=sql_text or "Truy vấn trực tiếp cột nhạy cảm (LUONG, CMND) với điều kiện LUONG >= 1000",
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item

        # 2.7. Phát hiện Leo thang đặc quyền & Backdoor (ids_priv_abuse_pol) -> CRITICAL (Score: 85, Level 3)
        if action in PRIV_ABUSE_ACTIONS and user != "SYS":
            alert_key = f"PRIV|{user}|{event_time}|{action}|{norm_sql[:40]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="CRITICAL",
                    risk_score=85,
                    event_time=event_time,
                    user=user,
                    attack_type=f"Privilege Escalation / Leo thang đặc quyền ({action})",
                    details=sql_text or f"Thực thi lệnh đặc quyền hệ thống vượt mức được cấp: {action} (ORA-{return_code})",
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item
        elif action in DDL_DANGEROUS_ACTIONS and user != "SYS":
            is_destructive = action in ("DROP TABLE", "TRUNCATE TABLE")
            ddl_score = 85 if is_destructive else 65
            ddl_sev = "CRITICAL" if is_destructive else "HIGH"
            alert_key = f"DDL|{user}|{event_time}|{action}|{norm_sql[:40]}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity=ddl_sev,
                    risk_score=ddl_score,
                    event_time=event_time,
                    user=user,
                    attack_type=f"Unauthorized DDL Modification ({action})",
                    details=sql_text or action,
                    row=row,
                )
                APP_STATE["alert_history"][alert_key] = item

        # 2.8. Thu thập chuỗi truy vấn phục vụ Statistical Inference (Count-based, Tracker, Linear System)
        # Bỏ qua các câu lệnh metadata nội bộ của SQL Developer / IDE
        is_metadata_query = any(meta in norm_sql for meta in ("ALL_OBJECTS", "DBA_", "USER$", "_CURRENT_EDITION_OBJ", "CAT ", "TAB ", "DUAL"))
        if user in stat_queries_by_user and action == "SELECT" and return_code == 0 and not is_metadata_query:
            if STAT_FUNC_PATTERNS.search(sql_text) and not HONEYTOKEN_PATTERNS.search(sql_text):
                m_where = WHERE_CLAUSE_PATTERN.search(sql_text)
                where_cond = m_where.group(1).strip() if m_where else "(ALL_ROWS)"
                stat_queries_by_user[user].append((event_time, sql_text, where_cond, row))
            elif "NV" in norm_sql:
                query_times_by_user[user].append((event_time, norm_sql, row))

        # 2.9. Phát hiện Công cụ kết nối bất thường (CLIENT_PROGRAM_NAME)
        if client_prog and SUSPICIOUS_CLIENTS.search(client_prog) and user in monitored_set:
            if user not in suspicious_client_by_user:
                suspicious_client_by_user[user] = (event_time, client_prog, sql_text or action, row)

    # -------------------------------------------------------------------------
    # 3. Phân tích Các Kiểu Tấn công Suy diễn vào CSDL Thống kê (SDB Inference Attacks):
    #    - Count-based Attack (Kết hợp COUNT = 1 và SUM)
    #    - Tracker Attack (Lách kiểm soát kích cỡ tập truy vấn bằng OR / != / NOT)
    #    - Linear System Attack (Thiết lập hệ phương trình tuyến tính A*X = B từ >= 3 truy vấn SUM/AVG)
    # -------------------------------------------------------------------------
    for user, q_list in stat_queries_by_user.items():
        if not q_list:
            continue
        unique_stat = q_list
        stat_count = len(unique_stat)
        latest_time, latest_sql, _, latest_row = unique_stat[0]
        distinct_wheres = {w.upper() for _, _, w, _ in unique_stat}
        upper_sqls = [s.upper() for _, s, _, _ in unique_stat]

        has_count = any("COUNT(" in s for s in upper_sqls)
        has_sum_or_avg = any("SUM(" in s or "AVG(" in s for s in upper_sqls)
        has_tracker_logic = any(
            (" OR " in w.upper() or "!=" in w.upper() or "<>" in w.upper() or "NOT " in w.upper())
            for _, _, w, _ in unique_stat
        )
        sum_query_count = sum(1 for s in upper_sqls if "SUM(" in s or "AVG(" in s)

        if stat_count >= 3:
            sample_queries = " ; ".join(s for _, s, _, _ in unique_stat[:4])
            if has_tracker_logic:
                sdb_type = "SDB Tracker Attack (Tấn công trình theo dõi lách Query-Set-Size)"
                sdb_score = 72
                sdb_desc = f"Thực hiện {stat_count} truy vấn thống kê sử dụng biểu thức phần bù/Tracker (OR/!=/NOT) trên {len(distinct_wheres)} tập con để cô lập hồ sơ cá nhân: {sample_queries}"
            elif sum_query_count >= 3 and len(distinct_wheres) >= 3:
                sdb_type = "SDB Linear System Attack (Tấn công giải hệ phương trình tuyến tính A*X=B)"
                sdb_score = 78
                sdb_desc = f"Thiết lập hệ phương trình tuyến tính từ {sum_query_count} truy vấn SUM/AVG chồng lấp trên {len(distinct_wheres)} tập con (Khử Gauss tìm toàn bộ LUONG): {sample_queries}"
            else:
                sdb_type = "SDB Count-based & Statistical Inference Attack (Tấn công suy diễn thống kê)"
                sdb_score = 65
                sdb_desc = f"Thực hiện liên tiếp {stat_count} truy vấn thống kê (COUNT/SUM/AVG) với {len(distinct_wheres)} điều kiện lọc: {sample_queries}"

            alert_key = f"STAT_INF|{user}|{latest_time}|{stat_count}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=sdb_score,
                    event_time=latest_time,
                    user=user,
                    attack_type=sdb_type,
                    details=sdb_desc,
                    row=latest_row,
                )
                APP_STATE["alert_history"][alert_key] = item
        elif stat_count == 2 and has_count and has_sum_or_avg:
            sample_queries = " ; ".join(s for _, s, _, _ in unique_stat[:2])
            alert_key = f"STAT_COUNT_SUM|{user}|{latest_time}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="HIGH",
                    risk_score=65,
                    event_time=latest_time,
                    user=user,
                    attack_type="SDB Count-based Attack (Tấn công dựa vào đếm COUNT=1 & SUM)",
                    details=f"Kết hợp truy vấn đếm COUNT(*) = 1 và tính tổng SUM(luong) trên cùng điều kiện lọc để suy diễn chính xác lương cá nhân: {sample_queries}",
                    row=latest_row,
                )
                APP_STATE["alert_history"][alert_key] = item
        elif 1 <= stat_count <= 2:
            alert_key = f"STAT_WARN|{user}|{latest_time}|{stat_count}"
            if alert_key not in APP_STATE["dismissed_keys"]:
                item = make_alert_item(
                    key=alert_key,
                    severity="LOW",
                    risk_score=28,
                    event_time=latest_time,
                    user=user,
                    attack_type="Suspicious Statistical Probe (Thăm dò thống kê SDB 1-2 lần)",
                    details=f"Phát hiện {stat_count} truy vấn hàm thống kê trên bảng nhạy cảm: {latest_sql}",
                    row=latest_row,
                )
                APP_STATE["alert_history"][alert_key] = item

    # -------------------------------------------------------------------------
    # 4. Phân tích Hành vi Đột biến (Bulk Querying trên bảng nghiệp vụ NV trong <= 5s)
    # -------------------------------------------------------------------------
    for user, q_events in query_times_by_user.items():
        if len(q_events) >= 10:
            times = [ev[0] for ev in q_events if len(ev[0]) >= 19]
            if len(times) >= 10:
                try:
                    from datetime import datetime
                    dt_max = datetime.strptime(max(times)[:19], "%Y-%m-%d %H:%M:%S")
                    dt_min = datetime.strptime(min(times)[:19], "%Y-%m-%d %H:%M:%S")
                    span_seconds = abs((dt_max - dt_min).total_seconds())
                    if span_seconds <= 5:
                        latest_time, _, latest_row = q_events[0]
                        alert_key = f"BULK|{user}|{latest_time[:16]}|{len(q_events)}"
                        if alert_key not in APP_STATE["dismissed_keys"]:
                            item = make_alert_item(
                                key=alert_key,
                                severity="MEDIUM",
                                risk_score=42,
                                event_time=latest_time,
                                user=user,
                                attack_type="Behavioral Anomaly: Tần suất truy vấn đột biến (Bulk Querying)",
                                details=f"Thực hiện dồn dập {len(q_events)} truy vấn trên bảng NV trong vòng {int(span_seconds)}s (nguy cơ Data Exfiltration)",
                                row=latest_row,
                            )
                            APP_STATE["alert_history"][alert_key] = item
                except Exception:
                    pass

    for user, (ev_time, c_prog, sql_txt, r_obj) in suspicious_client_by_user.items():
        alert_key = f"CLIENT|{user}|{c_prog}|{ev_time[:16]}"
        if alert_key not in APP_STATE["dismissed_keys"]:
            item = make_alert_item(
                key=alert_key,
                severity="MEDIUM",
                risk_score=38,
                event_time=ev_time,
                user=user,
                attack_type="Contextual Anomaly: Công cụ kết nối bất thường",
                details=f"Kết nối từ công cụ nghi vấn '{c_prog}' tại {r_obj.get('USERHOST', 'Unknown')}: {sql_txt}",
                row=r_obj,
            )
            APP_STATE["alert_history"][alert_key] = item

    save_persisted_state()

    # Thu thập toàn bộ cảnh báo hợp lệ từ alert_history
    alerts = []
    for k, item in list(APP_STATE.get("alert_history", {}).items()):
        u = item.get("user")
        t = item.get("time")
        if is_event_cleared(u, t) or k in APP_STATE.get("dismissed_keys", set()):
            continue
        alerts.append(item)

    alerts.sort(key=lambda x: (x.get("time", ""), x.get("risk_score", 0)), reverse=True)

    # -------------------------------------------------------------------------
    # 5. Tính toán Tổng Điểm Rủi Ro (User Risk Score 0-100) & Kích hoạt Phản ứng Đa cấp
    # -------------------------------------------------------------------------
    user_risk_summary = {}
    for user in sorted(user_info_map.keys()):
        u_info = user_info_map.get(user, {})
        active_user_alerts = [
            a for a in alerts if a["user"] == user and is_event_active_for_user_risk(user, a["time"])
        ]
        active_user_trigs = [
            t
            for t in trig_rows
            if str(t.get("DB_USER") or "").upper() == user
            and is_event_active_for_user_risk(user, str(t.get("EVENT_TIMESTAMP") or t.get("EVENT_TIME") or ""))
        ]

        # Tính điểm rủi ro tổng hợp cho User
        scores = [int(a["risk_score"]) for a in active_user_alerts]
        if active_user_trigs:
            scores.append(65 + min(12, (len(active_user_trigs) - 1) * 4))

        if not scores:
            total_score = 0
        else:
            max_s = max(scores)
            bonus = min(14, (len(scores) - 1) * 4)
            if max_s < 50:
                total_score = min(49, max_s + bonus)
            elif max_s < 80:
                total_score = min(79, max_s + bonus)
            else:
                total_score = min(100, max_s + bonus)

        lvl_num, lvl_label = classify_response_level(total_score)
        acct_status = str(u_info.get("ACCOUNT_STATUS") or "OPEN").upper()
        dml_status = str(u_info.get("DML_STATUS") or "FULL DML").upper()

        # Thực thi Phản ứng Chủ động Đa cấp (Graduated Active Response) nếu bật auto_block
        if auto_block:
            if lvl_num == 3 and "LOCK" not in acct_status:
                ok, _ = lock_user(user)
                if ok:
                    u_info["ACCOUNT_STATUS"] = "LOCKED"
                    auto_locked.append(user)
            elif lvl_num == 2 and "LOCK" not in acct_status and dml_status == "FULL DML":
                ok, _ = revoke_dml_user(user)
                if ok:
                    u_info["DML_STATUS"] = "READ-ONLY"
                    auto_revoked.append(user)

        user_risk_summary[user] = {
            "risk_score": total_score,
            "response_level": lvl_num,
            "response_label": lvl_label,
            "active_alerts": len(active_user_alerts),
        }

    return alerts, list(set(auto_locked)), list(set(auto_revoked)), user_risk_summary


def fetch_rows_as_dicts(cur, query, params=None):
    if params:
        cur.execute(query, params)
    else:
        cur.execute(query)
    cols = [col[0] for col in cur.description]
    result = []
    for row in cur.fetchall():
        item = {}
        for idx, val in enumerate(row):
            if hasattr(val, "read"):
                val = val.read()
            if isinstance(val, str):
                val = val.replace("\x00", "").strip()
            item[cols[idx]] = val if val is not None else ""
        result.append(item)
    return result


def fetch_user_dml_privileges(cur, usernames):
    """Kiểm tra quyền DML thực tế (INSERT, UPDATE, DELETE) của các User trên bảng NV."""
    priv_map = {u: set() for u in usernames}
    try:
        cur.execute(
            """
            SELECT grantee, privilege
            FROM dba_tab_privs
            WHERE table_name = 'NV'
              AND owner IN ('SYSTEM', 'SYS')
            """
        )
        for grantee, priv in cur.fetchall():
            if grantee in priv_map:
                priv_map[grantee].add(str(priv).upper())
    except Exception:
        pass
    return priv_map


def get_dashboard_data(do_flush=False):
    try:
        conn = get_connection()
        cur = conn.cursor()

        if do_flush:
            flush_audit_trail(cur)

        # Lấy danh sách động toàn bộ các User thực nghiệm (U1, U2, U3, U4, ...)
        query_users = """
            SELECT username AS USERNAME,
                   account_status AS ACCOUNT_STATUS,
                   TO_CHAR(lock_date, 'YYYY-MM-DD HH24:MI:SS') AS LOCK_DATE
            FROM dba_users
            WHERE oracle_maintained = 'N'
              AND username NOT IN ('PDBADMIN')
            ORDER BY username
        """
        initial_users = fetch_rows_as_dicts(cur, query_users)
        monitored_usernames = [u["USERNAME"] for u in initial_users] or ["U1", "U2", "U3", "U4"]
        in_clause = ", ".join(f"'{u}'" for u in monitored_usernames if re.match(r"^[A-Z0-9_#$]+$", u))
        if not in_clause:
            in_clause = "'U1', 'U2', 'U3', 'U4'"

        # Tự động cấp quyền mặc định & bật Audit Policy cho user mới tạo nếu chưa có quyền gì trên NV
        priv_map = fetch_user_dml_privileges(cur, monitored_usernames)
        for u_obj in initial_users:
            uname = u_obj["USERNAME"]
            if not priv_map.get(uname) and uname not in APP_STATE.get("initialized_users", set()):
                try:
                    cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO {uname}")
                    for pol in ("ids_ddl_pol", "ids_dml_nv_pol"):
                        try:
                            cur.execute(f"AUDIT POLICY {pol} BY {uname}")
                        except Exception:
                            pass
                except Exception:
                    pass
                APP_STATE.setdefault("initialized_users", set()).add(uname)
        priv_map = fetch_user_dml_privileges(cur, monitored_usernames)

        # 1. Lấy log truy vấn chung từ UNIFIED_AUDIT_TRAIL (chỉ lấy sau mốc reset alerts_cleared_at, loại bỏ truy vấn khởi tạo nội bộ của SQL Developer)
        cutoff_str = APP_STATE.get("alerts_cleared_at") or "1970-01-01 00:00:00"
        query_audit = f"""
            SELECT TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIMESTAMP,
                   dbusername AS DBUSERNAME,
                   action_name AS ACTION_NAME,
                   object_schema AS OBJECT_SCHEMA,
                   object_name AS OBJECT_NAME,
                   sql_text AS SQL_TEXT,
                   return_code AS RETURN_CODE,
                   os_username AS OS_USERNAME,
                   userhost AS USERHOST,
                   client_program_name AS CLIENT_PROGRAM_NAME,
                   audit_type AS AUDIT_TYPE,
                   fga_policy_name AS FGA_POLICY_NAME,
                   unified_audit_policies AS UNIFIED_AUDIT_POLICIES
            FROM unified_audit_trail
            WHERE dbusername IN ({in_clause})
              AND TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') > :cutoff
              AND NVL(object_name, 'NONE') NOT IN (
                  'DUAL', 'ALL_OBJECTS', 'ALL_TAB_COLS', 'ALL_SYNONYMS', 'ALL_TABLES',
                  'ALL_VIEWS', 'ALL_USERS', 'ALL_PROCEDURES', 'ALL_ARGUMENTS',
                  'ALL_CONSTRAINTS', 'ALL_INDEXES', 'ALL_TRIGGERS', 'ALL_SOURCE',
                  'NLS_SESSION_PARAMETERS', 'V$OPTION', 'V$VERSION', 'USER_ROLE_PRIVS',
                  'DATABASE_COMPATIBLE_LEVEL', 'USER_USERS', 'DBMS_APPLICATION_INFO', 'DBMS_OUTPUT'
              )
            ORDER BY event_timestamp DESC
            FETCH FIRST 250 ROWS ONLY
        """
        audit_rows = fetch_rows_as_dicts(cur, query_audit, {"cutoff": cutoff_str})

        # 2. Lấy chuyên biệt các sự kiện Fine-Grained Auditing (FGA & Honeytoken Traps)
        query_fga = f"""
            SELECT TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIMESTAMP,
                   dbusername AS DBUSERNAME,
                   action_name AS ACTION_NAME,
                   object_schema AS OBJECT_SCHEMA,
                   object_name AS OBJECT_NAME,
                   fga_policy_name AS FGA_POLICY_NAME,
                   audit_type AS AUDIT_TYPE,
                   sql_text AS SQL_TEXT,
                   os_username AS OS_USERNAME,
                   userhost AS USERHOST,
                   client_program_name AS CLIENT_PROGRAM_NAME,
                   return_code AS RETURN_CODE
            FROM unified_audit_trail
            WHERE dbusername IN ({in_clause})
              AND (audit_type = 'FineGrainedAudit' OR fga_policy_name IS NOT NULL)
              AND TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') > :cutoff
            ORDER BY event_timestamp DESC
            FETCH FIRST 50 ROWS ONLY
        """
        try:
            fga_cutoff = max(cutoff_str, APP_STATE.get("fga_cleared_at") or "")
            raw_fga_rows = fetch_rows_as_dicts(cur, query_fga, {"cutoff": fga_cutoff})
            dismissed_fga = APP_STATE.get("dismissed_fga_keys", set())
            # Lọc bỏ các dòng FGA_HONEYTOKEN_TRAP phát sinh phụ từ câu lệnh hàm thống kê (COUNT/SUM/AVG) không nhắm vào NV_TRAP
            fga_rows = [
                r
                for r in raw_fga_rows
                if not (
                    str(r.get("FGA_POLICY_NAME") or "").upper() == "FGA_HONEYTOKEN_TRAP"
                    and STAT_FUNC_PATTERNS.search(str(r.get("SQL_TEXT") or ""))
                    and not HONEYTOKEN_PATTERNS.search(str(r.get("SQL_TEXT") or ""))
                )
                and f"{r.get('EVENT_TIMESTAMP')}_{r.get('DBUSERNAME')}_{r.get('FGA_POLICY_NAME')}_{r.get('SQL_TEXT') or ''}"
                not in dismissed_fga
            ]
        except Exception:
            fga_rows = []

        # 3. Thống kê đăng nhập sai (Return code = 1017 là sai mật khẩu trong Oracle)
        query_failed_logon = """
            SELECT dbusername AS DBUSERNAME,
                   COUNT(*) AS FAIL_COUNT,
                   MAX(TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS')) AS LAST_ATTEMPT,
                   MAX(os_username) AS OS_USERNAME,
                   MAX(userhost) AS USERHOST,
                   MAX(client_program_name) AS CLIENT_PROGRAM_NAME
            FROM unified_audit_trail
            WHERE action_name = 'LOGON' AND return_code = 1017
              AND event_timestamp > SYSTIMESTAMP - INTERVAL '15' MINUTE
              AND TO_CHAR(event_timestamp, 'YYYY-MM-DD HH24:MI:SS') > :cutoff
            GROUP BY dbusername
        """
        failed_rows = fetch_rows_as_dicts(cur, query_failed_logon, {"cutoff": cutoff_str})

        # 4. Lấy cảnh báo từ Trigger nội sinh & FGA Handler Block
        query_trig = """
            SELECT alert_id AS ALERT_ID,
                   TO_CHAR(event_time, 'YYYY-MM-DD HH24:MI:SS') AS EVENT_TIME,
                   db_user AS DB_USER,
                   attack_type AS ATTACK_TYPE,
                   details AS DETAILS
            FROM SYS.IDS_TRIGGER_ALERTS
            ORDER BY event_time DESC
        """
        try:
            trig_rows = fetch_rows_as_dicts(cur, query_trig)
        except Exception:
            trig_rows = []

        # Bổ sung các sự kiện FGA_HONEYTOKEN_TRAP bị chặn tức thời (ORA-20003) vào danh sách hiển thị FGA
        try:
            fga_cutoff = max(cutoff_str, APP_STATE.get("fga_cleared_at") or "")
            dismissed_fga = APP_STATE.get("dismissed_fga_keys", set())
            existing_fga_sigs = {
                f"{r.get('EVENT_TIMESTAMP')}_{r.get('DBUSERNAME')}_{r.get('FGA_POLICY_NAME')}"
                for r in fga_rows
            }
            for tr in trig_rows:
                t_type = str(tr.get("ATTACK_TYPE") or "").upper()
                t_time = str(tr.get("EVENT_TIME") or "")
                t_user = str(tr.get("DB_USER") or "")
                t_sql = str(tr.get("DETAILS") or "")
                if ("HONEYTOKEN" in t_type or "SQL_INJECTION" in t_type) and (not fga_cutoff or t_time > fga_cutoff):
                    sig = f"{t_time}_{t_user}_FGA_HONEYTOKEN_TRAP"
                    fga_key = f"{t_time}_{t_user}_FGA_HONEYTOKEN_TRAP_{t_sql}"
                    if sig not in existing_fga_sigs and fga_key not in dismissed_fga:
                        fga_rows.append(
                            {
                                "EVENT_TIMESTAMP": t_time,
                                "DBUSERNAME": t_user,
                                "ACTION_NAME": "SELECT (BLOCKED ORA-20003)",
                                "OBJECT_SCHEMA": "SYS",
                                "OBJECT_NAME": "NV",
                                "FGA_POLICY_NAME": "FGA_HONEYTOKEN_TRAP",
                                "AUDIT_TYPE": "FineGrainedAudit",
                                "SQL_TEXT": t_sql,
                                "OS_USERNAME": "—",
                                "USERHOST": "SYS.IDS_FGA_TRAP_HANDLER",
                                "CLIENT_PROGRAM_NAME": "SQL Developer (Blocked)",
                                "RETURN_CODE": 20003,
                            }
                        )
                        existing_fga_sigs.add(sig)
            fga_rows.sort(key=lambda x: str(x.get("EVENT_TIMESTAMP") or ""), reverse=True)
        except Exception:
            pass

        user_info_map = {}
        for u in initial_users:
            uname = u["USERNAME"]
            u_privs = priv_map.get(uname, set())
            has_dml = any(p in u_privs for p in ("INSERT", "UPDATE", "DELETE"))
            u["DML_STATUS"] = "FULL DML" if has_dml else "READ-ONLY"
            u["PRIVILEGES"] = ", ".join(sorted(u_privs)) if u_privs else "NONE"
            user_info_map[uname] = u

        # 6. Phân tích đa chiều, tính Risk Score (0-100) & Kích hoạt Phản ứng Đa cấp (Level 1 / 2 / 3)
        alerts, auto_locked, auto_revoked, user_risk_summary = analyze_audit_logs(
            audit_rows,
            failed_rows,
            trig_rows,
            user_info_map,
            auto_block=APP_STATE["auto_response"],
        )

        # 7. Nếu vừa tự động khóa hoặc hạ quyền DML, cập nhật lại danh sách User & Quyền
        if auto_locked or auto_revoked:
            user_rows = fetch_rows_as_dicts(cur, query_users)
            priv_map = fetch_user_dml_privileges(cur, monitored_usernames)
        else:
            user_rows = initial_users

        for u in user_rows:
            uname = u["USERNAME"]
            u_privs = priv_map.get(uname, set())
            has_dml = any(p in u_privs for p in ("INSERT", "UPDATE", "DELETE"))
            u["DML_STATUS"] = "FULL DML" if has_dml else "READ-ONLY"
            u["PRIVILEGES"] = ", ".join(sorted(u_privs)) if u_privs else "NONE"
            r_sum = user_risk_summary.get(uname, {})
            u["RISK_SCORE"] = r_sum.get("risk_score", 0)
            u["RESPONSE_LEVEL"] = r_sum.get("response_level", 0)
            u["RESPONSE_LABEL"] = r_sum.get("response_label", "Level 0: Normal (An toàn)")

        # 8. Lấy dữ liệu bảng nhạy cảm SYS.NV (kèm bản ghi bẫy Honeytoken NV_TRAP)
        query_nv = """
            SELECT manv AS MANV,
                   hoten AS HOTEN,
                   luong AS LUONG,
                   gioitinh AS GIOITINH,
                   cmnd AS CMND
            FROM SYS.NV
            ORDER BY CASE WHEN manv = 'NV_TRAP' THEN 1 ELSE 0 END, manv
        """
        try:
            nv_rows = fetch_rows_as_dicts(cur, query_nv)
        except Exception:
            nv_rows = []

        cur.close()
        conn.close()

        locked_count = sum(
            1 for u in user_rows if "LOCK" in str(u.get("ACCOUNT_STATUS", "")).upper()
        )
        readonly_count = sum(
            1 for u in user_rows if str(u.get("DML_STATUS", "")).upper() == "READ-ONLY"
        )
        max_risk = max((int(u.get("RISK_SCORE", 0)) for u in user_rows), default=0)

        audit_cutoff = max(cutoff_str, APP_STATE.get("audit_cleared_at") or "")
        dismissed_audit = APP_STATE.get("dismissed_audit_keys", set())
        ide_meta_keywords = (
            "FROM ALL_OBJECTS",
            "FROM ALL_TAB_COLS",
            "FROM ALL_SYNONYMS",
            "FROM ALL_TABLES",
            "FROM ALL_VIEWS",
            "FROM ALL_USERS",
            "FROM ALL_PROCEDURES",
            "FROM ALL_ARGUMENTS",
            "FROM ALL_CONSTRAINTS",
            "FROM ALL_INDEXES",
            "FROM ALL_TRIGGERS",
            "FROM ALL_SOURCE",
            "_CURRENT_EDITION_OBJ",
            "NLS_SESSION_PARAMETERS",
            "DBMS_APPLICATION_INFO",
            "DBMS_OUTPUT.",
            "FROM DUAL",
            "FROM SYS.DUAL",
            "DATABASE_COMPATIBLE_LEVEL",
            "V$OPTION",
            "V$VERSION",
            "USER_ROLE_PRIVS",
            "USER_USERS",
            "DG_COUNT",
            "TAB_COUNT",
            "INST_COUNT",
            "SYS_CONTEXT('USERENV', 'CON_ID')",
            "SYS_CONTEXT('USERENV', 'SERVICE_NAME')",
        )
        display_audit_rows = [
            r
            for r in audit_rows
            if (not audit_cutoff or str(r.get("EVENT_TIMESTAMP") or "") > audit_cutoff)
            and not any(kw in re.sub(r"\s+", " ", str(r.get("SQL_TEXT") or "")).upper() for kw in ide_meta_keywords)
            and f"{r.get('EVENT_TIMESTAMP')}_{r.get('DBUSERNAME')}_{r.get('ACTION_NAME')}_{(r.get('SQL_TEXT') or '')[:40]}"
            not in dismissed_audit
        ]

        return {
            "ok": True,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dsn": DB_DSN,
            "auto_response": APP_STATE["auto_response"],
            "alerts_cleared_at": APP_STATE["alerts_cleared_at"],
            "auto_locked": auto_locked,
            "auto_revoked": auto_revoked,
            "metrics": {
                "audit_count": len(display_audit_rows),
                "alert_count": len(alerts),
                "trigger_count": len(trig_rows),
                "fga_count": len(fga_rows),
                "locked_count": locked_count,
                "readonly_count": readonly_count,
                "max_risk": max_risk,
            },
            "users": user_rows,
            "alerts": alerts,
            "fga_events": fga_rows,
            "triggers": trig_rows,
            "audit_logs": display_audit_rows,
            "failed_logons": failed_rows,
            "employees": nv_rows,
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dsn": DB_DSN,
            "auto_response": APP_STATE["auto_response"],
        }


# ================= GIAO DIỆN WEB HIỆN ĐẠI (DARK MODE + DEFENSE-IN-DEPTH UI) =================
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Oracle DB-IDS | Defense-in-Depth &amp; Active IPS</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    /* ==========================================================================
       MINIMALIST CYBERSECURITY SOC DESIGN SYSTEM
       Dark Navy + Clean Blue Accents + Flat Crisp Surfaces
       ========================================================================== */
    :root {
      /* Backgrounds */
      --bg-canvas: #090e17;
      --bg-surface: #0e1626;
      --bg-surface-elevated: #131e33;
      --bg-card: #101b2e;
      --bg-card-hover: #15233c;
      --bg-input: #0b1322;
      --bg-row-hover: rgba(30, 48, 80, 0.35);

      /* Borders */
      --border-subtle: rgba(255, 255, 255, 0.06);
      --border: rgba(56, 189, 248, 0.14);
      --border-hover: rgba(56, 189, 248, 0.3);
      --border-accent: #0284c7;

      /* Typography */
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --text-accent: #38bdf8;

      /* Accents */
      --accent-blue: #0ea5e9;
      --accent-blue-soft: rgba(14, 165, 233, 0.12);
      --accent-purple: #8b5cf6;
      --accent-purple-soft: rgba(139, 92, 246, 0.12);

      /* Severity Colors */
      --crit-red: #ef4444;
      --crit-soft: rgba(239, 68, 68, 0.12);
      --crit-border: rgba(239, 68, 68, 0.35);

      --high-orange: #f97316;
      --high-soft: rgba(249, 115, 22, 0.12);
      --high-border: rgba(249, 115, 22, 0.35);

      --med-yellow: #eab308;
      --med-soft: rgba(234, 179, 8, 0.12);
      --med-border: rgba(234, 179, 8, 0.35);

      --safe-green: #10b981;
      --safe-soft: rgba(16, 185, 129, 0.12);
      --safe-border: rgba(16, 185, 129, 0.35);

      /* Geometry */
      --radius-lg: 10px;
      --radius-md: 8px;
      --radius-sm: 6px;
      --radius-pill: 999px;
      --shadow-card: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-canvas);
      color: var(--text-primary);
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      display: flex;
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* Custom Scrollbars */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: var(--bg-canvas);
    }
    ::-webkit-scrollbar-thumb {
      background: rgba(56, 189, 248, 0.2);
      border-radius: var(--radius-pill);
    }
    ::-webkit-scrollbar-thumb:hover {
      background: rgba(56, 189, 248, 0.4);
    }

    /* ==========================================================================
       1. SIDEBAR (MINIMALIST & CLEAN)
       ========================================================================== */
    .sidebar {
      width: 260px;
      background-color: var(--bg-surface);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0;
      bottom: 0;
      left: 0;
      z-index: 50;
      overflow-y: auto;
    }

    .brand {
      padding: 20px 18px 18px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-logo-wrap {
      width: 38px;
      height: 38px;
      border-radius: 9px;
      background: linear-gradient(135deg, rgba(14, 165, 233, 0.2) 0%, rgba(2, 132, 199, 0.4) 100%);
      border: 1px solid rgba(56, 189, 248, 0.35);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #38bdf8;
      flex-shrink: 0;
    }
    .brand-logo-wrap svg {
      width: 20px;
      height: 20px;
    }
    .brand-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      letter-spacing: -0.01em;
    }
    .brand-subtitle {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 1px;
    }

    .nav-section {
      padding: 14px 10px;
      flex: 1;
    }
    .nav-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 9px 12px;
      border-radius: var(--radius-md);
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 12.5px;
      cursor: pointer;
      transition: all 0.15s ease;
      user-select: none;
      border: 1px solid transparent;
    }
    .nav-item-left {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }
    .nav-logo {
      width: 18px;
      height: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--text-muted);
      flex-shrink: 0;
    }
    .nav-logo svg {
      width: 17px;
      height: 17px;
      stroke-width: 2;
    }
    .nav-item:hover {
      background-color: var(--bg-surface-elevated);
      color: var(--text-primary);
    }
    .nav-item:hover .nav-logo {
      color: var(--text-accent);
    }
    .nav-item.active {
      background-color: #0284c7;
      color: #ffffff;
      border-color: #38bdf8;
    }
    .nav-item.active .nav-logo {
      color: #ffffff;
    }

    .nav-badge {
      font-size: 10.5px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      padding: 1px 6px;
      border-radius: var(--radius-pill);
      background: var(--crit-soft);
      color: #fca5a5;
      border: 1px solid var(--crit-border);
    }
    .nav-badge.orange {
      background: var(--high-soft);
      color: #fdba74;
      border-color: var(--high-border);
    }
    .nav-badge.purple {
      background: var(--accent-purple-soft);
      color: #d8b4fe;
      border-color: rgba(139, 92, 246, 0.35);
    }
    .nav-badge.blue {
      background: var(--accent-blue-soft);
      color: #7dd3fc;
      border-color: rgba(14, 165, 233, 0.35);
    }

    /* Sidebar Footer Status (Minimalist matching reference image) */
    .sidebar-footer {
      padding: 16px 18px;
      border-top: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .pulse-dot-large {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--safe-green);
      box-shadow: 0 0 10px var(--safe-green);
      flex-shrink: 0;
    }
    .footer-status-title {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .footer-status-sub {
      font-size: 11px;
      color: var(--safe-green);
      font-weight: 600;
    }

    /* ==========================================================================
       2. HEADER / TOPBAR
       ========================================================================== */
    .main {
      margin-left: 260px;
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
    }

    .topbar {
      height: 64px;
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border);
      padding: 0 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 40;
    }
    .topbar-left {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }
    .pulse-wave-icon {
      color: var(--accent-blue);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .pulse-wave-icon svg {
      width: 24px;
      height: 24px;
    }
    .topbar-title h2 {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      letter-spacing: -0.01em;
    }
    .topbar-title p {
      font-size: 11px;
      color: var(--text-secondary);
      margin-top: 1px;
    }

    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-shrink: 0;
    }
    .conn-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 6px 12px;
      border-radius: var(--radius-pill);
      background: var(--bg-card);
      border: 1px solid var(--border);
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
    }
    .status-dot-sm {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--safe-green);
      box-shadow: 0 0 6px var(--safe-green);
    }
    .status-dot-sm.offline {
      background: var(--crit-red);
      box-shadow: 0 0 6px var(--crit-red);
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 7px 14px;
      border-radius: var(--radius-md);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--bg-surface-elevated);
      color: var(--text-primary);
      transition: all 0.15s ease;
      font-family: inherit;
      white-space: nowrap;
      user-select: none;
    }
    .btn svg {
      width: 14px;
      height: 14px;
      flex-shrink: 0;
    }
    .btn:hover {
      background: var(--bg-card-hover);
      border-color: var(--border-hover);
    }
    .btn-primary {
      background: #0284c7;
      border-color: #38bdf8;
      color: #ffffff;
    }
    .btn-primary:hover {
      background: #0369a1;
    }
    .btn-danger-outline {
      background: transparent;
      border-color: var(--crit-border);
      color: #fca5a5;
    }
    .btn-danger-outline:hover {
      background: var(--crit-soft);
      border-color: var(--crit-red);
    }
    .btn-warning-outline {
      background: transparent;
      border-color: var(--high-border);
      color: #fdba74;
    }
    .btn-warning-outline:hover {
      background: var(--high-soft);
      border-color: var(--high-orange);
    }
    .btn-sm {
      padding: 4px 10px;
      font-size: 11px;
      border-radius: var(--radius-sm);
    }

    /* Content Area */
    .content {
      padding: 20px 24px 40px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    /* ==========================================================================
       3. KPI CARDS (MATCHING REFERENCE IMAGE)
       ========================================================================== */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }
    .kpi-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 16px 18px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      box-shadow: var(--shadow-card);
      position: relative;
    }
    .kpi-top {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .kpi-icon-pill {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .kpi-blue .kpi-icon-pill {
      background: var(--accent-blue-soft);
      color: var(--accent-blue);
      border: 1px solid rgba(14, 165, 233, 0.25);
    }
    .kpi-red .kpi-icon-pill {
      background: var(--crit-soft);
      color: var(--crit-red);
      border: 1px solid var(--crit-border);
    }
    .kpi-yellow .kpi-icon-pill {
      background: var(--high-soft);
      color: var(--high-orange);
      border: 1px solid var(--high-border);
    }
    .kpi-purple .kpi-icon-pill {
      background: var(--accent-purple-soft);
      color: var(--accent-purple);
      border: 1px solid rgba(139, 92, 246, 0.25);
    }
    .kpi-icon-pill svg {
      width: 17px;
      height: 17px;
    }
    .kpi-title {
      font-size: 12px;
      color: var(--text-secondary);
      font-weight: 600;
    }

    .kpi-body {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      margin-top: 14px;
    }
    .kpi-stat-group {
      display: flex;
      flex-direction: column;
    }
    .kpi-number {
      font-size: 26px;
      font-weight: 800;
      color: var(--text-primary);
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.1;
    }
    .kpi-subtext {
      font-size: 11px;
      margin-top: 6px;
      font-weight: 600;
    }
    .kpi-subtext.green { color: var(--safe-green); }
    .kpi-subtext.red { color: var(--crit-red); }
    .kpi-subtext.yellow { color: var(--high-orange); }
    .kpi-subtext.muted { color: var(--text-muted); }

    .kpi-chart-wrap {
      width: 65px;
      height: 34px;
      display: flex;
      align-items: flex-end;
      justify-content: flex-end;
      flex-shrink: 0;
    }

    /* ==========================================================================
       4. CARDS, TABLES & SECTIONS
       ========================================================================== */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-card);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      min-width: 0;
    }

    .card-header {
      padding: 13px 18px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: rgba(14, 22, 38, 0.4);
      flex-wrap: wrap;
      gap: 10px;
    }
    .card-title-left {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }
    .card-header-icon {
      color: var(--accent-blue);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .card-header-icon.red { color: var(--crit-red); }
    .card-header-icon.yellow { color: var(--high-orange); }
    .card-header-icon.purple { color: var(--accent-purple); }
    .card-header-icon svg {
      width: 17px;
      height: 17px;
    }
    .card-title-text {
      font-size: 13.5px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .card-subtitle-text {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 1px;
    }

    .card-tools {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .card-link {
      font-size: 12px;
      color: var(--text-accent);
      text-decoration: none;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: color 0.15s ease;
    }
    .card-link:hover {
      color: #ffffff;
      text-decoration: underline;
    }

    .search-input {
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      color: var(--text-primary);
      padding: 6px 12px;
      font-size: 11.5px;
      outline: none;
      width: 220px;
      font-family: inherit;
      transition: border-color 0.15s ease;
    }
    .search-input:focus {
      border-color: var(--border-accent);
    }

    /* Tables */
    .table-wrap {
      width: 100%;
      overflow-x: auto;
      max-height: 480px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th {
      position: sticky;
      top: 0;
      background: #0b1322;
      color: var(--text-muted);
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      z-index: 10;
      white-space: nowrap;
    }
    td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 12px;
      color: var(--text-primary);
      vertical-align: middle;
    }
    tr:last-child td {
      border-bottom: none;
    }
    tbody tr:hover {
      background-color: var(--bg-row-hover);
    }
    tbody tr.clickable-row {
      cursor: pointer;
    }
    tbody tr.honeytoken-row {
      background-color: rgba(239, 68, 68, 0.08);
    }
    tbody tr.honeytoken-row:hover {
      background-color: rgba(239, 68, 68, 0.15);
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 11.5px;
      white-space: nowrap;
    }
    .sql-code {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 11px;
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      padding: 2px 7px;
      border-radius: 4px;
      color: #7dd3fc;
      display: inline-block;
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      vertical-align: middle;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: var(--radius-pill);
      font-size: 10.5px;
      font-weight: 700;
      white-space: nowrap;
      letter-spacing: 0.02em;
    }
    .badge-critical {
      background: transparent;
      color: #fca5a5;
      border: 1px solid var(--crit-red);
    }
    .badge-high {
      background: transparent;
      color: #fdba74;
      border: 1px solid var(--high-orange);
    }
    .badge-medium {
      background: transparent;
      color: #fde047;
      border: 1px solid var(--med-yellow);
    }
    .badge-success {
      background: transparent;
      color: #6ee7b7;
      border: 1px solid var(--safe-green);
    }
    .badge-neutral {
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      border: 1px solid var(--border-subtle);
    }

    /* Risk Score Indicator */
    .risk-inline {
      display: inline-flex;
      align-items: center;
      gap: 7px;
    }
    .risk-score-text {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      min-width: 44px;
    }
    .risk-bar-track {
      width: 45px;
      height: 4px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: var(--radius-pill);
      overflow: hidden;
    }
    .risk-bar-prog {
      height: 100%;
      border-radius: var(--radius-pill);
    }

    /* 2-column grid for overview bottom */
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    /* Empty state */
    .empty-state {
      padding: 32px 18px;
      text-align: center;
      color: var(--text-secondary);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      font-size: 12.5px;
    }
    .empty-state svg {
      width: 28px;
      height: 28px;
      color: var(--safe-green);
    }

    /* Dedicated Tab Container Controls */
    .tab-view {
      display: none;
      flex-direction: column;
      gap: 18px;
    }
    .tab-view.active {
      display: flex;
    }

    /* Filter buttons */
    .filter-group {
      display: flex;
      align-items: center;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 2px;
      gap: 2px;
    }
    .filter-btn {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 600;
      border-radius: var(--radius-sm);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-btn:hover { color: var(--text-primary); }
    .filter-btn.active {
      background: rgba(56, 189, 248, 0.18);
      color: var(--text-accent);
    }

    /* ==========================================================================
       5. MODAL & TOAST NOTIFICATIONS
       ========================================================================== */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(4, 7, 15, 0.8);
      backdrop-filter: blur(4px);
      z-index: 150;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .modal-backdrop.open {
      display: flex;
    }
    .modal-box {
      background: #0f192b;
      border: 1px solid var(--border-hover);
      border-radius: var(--radius-lg);
      width: 100%;
      max-width: 720px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7);
      overflow: hidden;
    }
    .modal-header {
      padding: 14px 18px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #0c1424;
    }
    .modal-title {
      font-size: 13.5px;
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .modal-close {
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 4px;
      border-radius: var(--radius-sm);
      display: flex;
    }
    .modal-close:hover {
      color: #ffffff;
      background: rgba(255, 255, 255, 0.08);
    }
    .modal-body {
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      max-height: 72vh;
      overflow-y: auto;
    }
    .detail-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px 14px;
    }
    .detail-item {
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 12px;
    }
    .detail-label {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.04em;
      margin-bottom: 3px;
    }
    .detail-val {
      font-size: 12px;
      color: var(--text-primary);
      font-weight: 500;
      word-break: break-all;
    }
    .sql-full-box {
      background: #070d18;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 12px;
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 11.5px;
      color: #7dd3fc;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 200px;
      overflow-y: auto;
      line-height: 1.5;
    }
    .modal-footer {
      padding: 12px 18px;
      border-top: 1px solid var(--border-subtle);
      background: #0c1424;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }

    .toast-container {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 200;
      display: flex;
      flex-direction: column;
      gap: 8px;
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      background: #111e33;
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent-blue);
      color: var(--text-primary);
      padding: 10px 14px;
      border-radius: var(--radius-md);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
      font-size: 12px;
      display: flex;
      align-items: center;
      gap: 9px;
      max-width: 380px;
    }
    .toast.success { border-left-color: var(--safe-green); }
    .toast.error { border-left-color: var(--crit-red); }
    .toast svg { width: 16px; height: 16px; flex-shrink: 0; }
    .toast.success svg { color: var(--safe-green); }
    .toast.error svg { color: var(--crit-red); }

    /* Cyber switch for IPS page */
    .switch-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      margin-bottom: 8px;
    }
    .switch {
      position: relative;
      display: inline-block;
      width: 36px;
      height: 18px;
      flex-shrink: 0;
    }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; inset: 0;
      background: #334155; border-radius: var(--radius-pill); transition: 0.2s;
    }
    .slider:before {
      position: absolute; content: ""; height: 12px; width: 12px;
      left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.2s;
    }
    input:checked + .slider { background: #0284c7; }
    input:checked + .slider:before { transform: translateX(18px); }

    .spin { animation: rotate 0.8s linear infinite; }
    @keyframes rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

    @media (max-width: 1200px) {
      .kpi-grid { grid-template-columns: repeat(2, 1fr); }
      .grid-2 { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>

  <!-- ==========================================================================
       SIDEBAR
       ========================================================================== -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-logo-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
      </div>
      <div>
        <div class="brand-title">Oracle DB-IDS</div>
        <div class="brand-subtitle">Defense-in-Depth &amp; Active IPS</div>
      </div>
    </div>

    <!-- Nav List -->
    <div class="nav-section">
      <ul class="nav-list">
        <li class="nav-item active" onclick="switchTab('home', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 9.5L12 3l9 6.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1V9.5z"/>
              </svg>
            </span>
            <span>Tổng quan SOC</span>
          </div>
        </li>

        <li class="nav-item" onclick="switchTab('alerts', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </span>
            <span>Cảnh báo &amp; Risk Score</span>
          </div>
          <span class="nav-badge" id="nav-alert-count">0</span>
        </li>

        <li class="nav-item" onclick="switchTab('fga', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2"/>
                <polyline points="2 17 12 22 22 17"/>
                <polyline points="2 12 12 17 22 12"/>
              </svg>
            </span>
            <span>Bẫy FGA &amp; Honeytoken</span>
          </div>
        </li>

        <li class="nav-item" onclick="switchTab('triggers', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
              </svg>
            </span>
            <span>Trigger chặn tức thời</span>
          </div>
        </li>

        <li class="nav-item" onclick="switchTab('audit', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
                <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
              </svg>
            </span>
            <span>Nhật ký kiểm toán</span>
          </div>
        </li>

        <li class="nav-item" onclick="switchTab('users', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                <circle cx="12" cy="7" r="4"/>
              </svg>
            </span>
            <span>Tài khoản &amp; Dữ liệu NV</span>
          </div>
        </li>

        <li class="nav-item" onclick="switchTab('ips', this)">
          <div class="nav-item-left">
            <span class="nav-logo">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </span>
            <span>Phản ứng Đa cấp (IPS)</span>
          </div>
        </li>
      </ul>
    </div>

    <!-- Minimalist Sidebar Footer (Matching reference image) -->
    <div class="sidebar-footer">
      <div class="pulse-dot-large"></div>
      <div>
        <div class="footer-status-title">Oracle 23ai Security</div>
        <div class="footer-status-sub">Online</div>
      </div>
    </div>
  </aside>

  <!-- ==========================================================================
       MAIN CONTENT
       ========================================================================== -->
  <div class="main">
    <!-- Header / Topbar (Matching reference image) -->
    <header class="topbar">
      <div class="topbar-left">
        <div class="pulse-wave-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
          </svg>
        </div>
        <div class="topbar-title">
          <h2 id="topbar-heading">Trung tâm Giám sát An ninh CSDL</h2>
          <p id="topbar-subheading">Oracle 23ai DB-IDS • Honeytoken Canary • Thống kê &amp; Phòng thủ thông minh</p>
        </div>
      </div>

      <div class="topbar-actions">
        <div class="conn-pill">
          <span class="status-dot-sm" id="conn-dot"></span>
          <span id="conn-text">localhost:1521/FREEPDB1</span>
        </div>
        <button class="btn btn-primary" onclick="refreshData(true)">
          <svg id="refresh-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="23 4 23 10 17 10"/>
            <polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
          <span>Làm mới dữ liệu (Flush Audit)</span>
        </button>
      </div>
    </header>

    <main class="content">

      <!-- ====================================================================
           TAB 1: TỔNG QUAN SOC (OVERVIEW)
           KPIs + Cảnh báo IDS + Preview Bẫy FGA (Xem chi tiết) + Preview Trigger (Xem chi tiết)
           ==================================================================== -->
      <div class="tab-view active" id="tab-home">
        <!-- 4 KPI Cards (Matching reference image) -->
        <section class="kpi-grid">
          <!-- Card 1: Tổng sự kiện Audit & FGA -->
          <div class="kpi-card kpi-blue">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <ellipse cx="12" cy="5" rx="9" ry="3"/>
                  <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                  <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                </svg>
              </div>
              <div class="kpi-title">Tổng sự kiện Audit &amp; FGA</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="kpi-audit">18</div>
                <div class="kpi-subtext green">↑ +12% so với trước đó</div>
              </div>
              <div class="kpi-chart-wrap">
                <!-- Mini Bar chart SVG -->
                <svg width="60" height="30" viewBox="0 0 60 30" fill="none">
                  <rect x="2" y="16" width="6" height="14" rx="2" fill="#0284c7" opacity="0.6"/>
                  <rect x="12" y="12" width="6" height="18" rx="2" fill="#0284c7" opacity="0.75"/>
                  <rect x="22" y="18" width="6" height="12" rx="2" fill="#0284c7" opacity="0.6"/>
                  <rect x="32" y="8" width="6" height="22" rx="2" fill="#0284c7" opacity="0.85"/>
                  <rect x="42" y="4" width="6" height="26" rx="2" fill="#38bdf8"/>
                  <rect x="52" y="10" width="6" height="20" rx="2" fill="#0284c7"/>
                </svg>
              </div>
            </div>
          </div>

          <!-- Card 2: Cảnh báo IDS đa chiều -->
          <div class="kpi-card kpi-red">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              </div>
              <div class="kpi-title">Cảnh báo IDS đa chiều</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="kpi-alerts">5</div>
                <div class="kpi-subtext red">↑ +1 mới</div>
              </div>
              <div class="kpi-chart-wrap">
                <!-- Mini Red Sparkline SVG -->
                <svg width="65" height="30" viewBox="0 0 65 30" fill="none">
                  <path d="M2 24 Q 15 26, 25 15 T 45 18 T 63 4" stroke="#ef4444" stroke-width="2.5" fill="none" stroke-linecap="round"/>
                  <path d="M2 24 Q 15 26, 25 15 T 45 18 T 63 4 L 63 30 L 2 30 Z" fill="url(#red-spark-grad)" opacity="0.3"/>
                  <defs>
                    <linearGradient id="red-spark-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stop-color="#ef4444"/>
                      <stop offset="100%" stop-color="#ef4444" stop-opacity="0"/>
                    </linearGradient>
                  </defs>
                </svg>
              </div>
            </div>
          </div>

          <!-- Card 3: Vi phạm bị Trigger chặn -->
          <div class="kpi-card kpi-yellow">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                </svg>
              </div>
              <div class="kpi-title">Vi phạm bị Trigger chặn</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="kpi-triggers">2</div>
                <div class="kpi-subtext green">↓ Đã xử lý</div>
              </div>
              <div class="kpi-chart-wrap">
                <!-- Mini Yellow Sparkline SVG -->
                <svg width="65" height="30" viewBox="0 0 65 30" fill="none">
                  <path d="M2 22 Q 18 10, 32 20 T 63 8" stroke="#f97316" stroke-width="2.5" fill="none" stroke-linecap="round"/>
                  <path d="M2 22 Q 18 10, 32 20 T 63 8 L 63 30 L 2 30 Z" fill="url(#yellow-spark-grad)" opacity="0.3"/>
                  <defs>
                    <linearGradient id="yellow-spark-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stop-color="#f97316"/>
                      <stop offset="100%" stop-color="#f97316" stop-opacity="0"/>
                    </linearGradient>
                  </defs>
                </svg>
              </div>
            </div>
          </div>

          <!-- Card 4: Định mức rủi ro & Phản ứng IPS -->
          <div class="kpi-card kpi-purple">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="10"/>
                  <polygon points="12 6 12 12 16 14"/>
                </svg>
              </div>
              <div class="kpi-title">Định mức rủi ro &amp; Phản ứng IPS</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="kpi-locked">100 / 100</div>
                <div class="kpi-subtext muted" id="kpi-ips-sub">Khóa (L3): 2 | Read-Only (L2): 1</div>
              </div>
              <div class="kpi-chart-wrap">
                <!-- Mini Donut SVG -->
                <svg width="34" height="34" viewBox="0 0 36 36">
                  <circle cx="18" cy="18" r="14" fill="none" stroke="rgba(139,92,246,0.2)" stroke-width="4"/>
                  <circle cx="18" cy="18" r="14" fill="none" stroke="#a855f7" stroke-width="4" stroke-dasharray="88" stroke-dashoffset="20" stroke-linecap="round"/>
                </svg>
              </div>
            </div>
          </div>
        </section>

        <!-- Main Alert Table for Overview -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon red">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                  <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Cảnh báo Phân tích Đa chiều &amp; Chấm điểm Rủi ro (IDS Detection Engine)</div>
              </div>
            </div>
            <div class="card-tools">
              <input type="text" id="home-alert-search" class="search-input" placeholder="🔍 Tìm kiếm..." oninput="renderHomeAlerts()" />
              <button class="btn btn-sm btn-danger-outline" onclick="clearAlerts('ids')" title="Xóa lịch sử cảnh báo IDS">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="3 6 5 6 21 6"/>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                </svg>
                <span>Xóa cảnh báo</span>
              </button>
            </div>
          </div>
          <div class="table-wrap" id="home-alerts-container"></div>
        </section>

        <!-- Bottom 2-card section with "Xem chi tiết →" (matching reference image) -->
        <section class="grid-2">
          <!-- Card Left: FGA & Honeytoken Preview -->
          <div class="card">
            <div class="card-header">
              <div class="card-title-left">
                <div class="card-header-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                  </svg>
                </div>
                <div class="card-title-text">Sự kiện Kiểm toán &amp; Bẫy Dữ liệu (DBMS_FGA &amp; Honeytoken)</div>
              </div>
              <span class="card-link" onclick="switchTab('fga')">Xem chi tiết →</span>
            </div>
            <div class="table-wrap" id="home-fga-container"></div>
          </div>

          <!-- Card Right: Trigger Preview -->
          <div class="card">
            <div class="card-header">
              <div class="card-title-left">
                <div class="card-header-icon yellow">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <ellipse cx="12" cy="5" rx="9" ry="3"/>
                    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                  </svg>
                </div>
                <div class="card-title-text">Hành vi bị chặn tức thời bởi Database Trigger</div>
              </div>
              <span class="card-link" onclick="switchTab('triggers')">Xem chi tiết →</span>
            </div>
            <div class="table-wrap" id="home-triggers-container"></div>
          </div>
        </section>
      </div>

      <!-- ====================================================================
           TAB 2: CẢNH BÁO & RISK SCORE (ALERTS ONLY)
           4 KPI Cards + 1 Unique IDS Detection Engine table (filters, search, details)
           ==================================================================== -->
      <div class="tab-view" id="tab-alerts">
        <!-- 4 KPI Cards (Kept on top as requested) -->
        <section class="kpi-grid">
          <div class="kpi-card kpi-blue">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
              </div>
              <div class="kpi-title">Tổng sự kiện Audit &amp; FGA</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="alerts-kpi-audit">18</div>
                <div class="kpi-subtext green">Hệ thống giám sát ổn định</div>
              </div>
            </div>
          </div>

          <div class="kpi-card kpi-red">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              </div>
              <div class="kpi-title">Cảnh báo IDS đa chiều</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="alerts-kpi-alerts">5</div>
                <div class="kpi-subtext red">Cần phân tích &amp; xử lý</div>
              </div>
            </div>
          </div>

          <div class="kpi-card kpi-yellow">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
              </div>
              <div class="kpi-title">Vi phạm bị Trigger chặn</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="alerts-kpi-triggers">2</div>
                <div class="kpi-subtext green">Chặn tức thì bởi Trigger</div>
              </div>
            </div>
          </div>

          <div class="kpi-card kpi-purple">
            <div class="kpi-top">
              <div class="kpi-icon-pill">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>
              </div>
              <div class="kpi-title">Đỉnh rủi ro &amp; Phản ứng IPS</div>
            </div>
            <div class="kpi-body">
              <div class="kpi-stat-group">
                <div class="kpi-number" id="alerts-kpi-locked">100 / 100</div>
                <div class="kpi-subtext muted" id="alerts-kpi-ips-sub">Cách ly tự động cấp 3</div>
              </div>
            </div>
          </div>
        </section>

        <!-- Unique IDS Detection Engine Table -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon red">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Trung tâm Cảnh báo Xâm nhập &amp; Đánh giá Rủi ro (IDS Detection Engine)</div>
                <div class="card-subtitle-text">Phát hiện Honeytoken Trap, Thống kê suy diễn (SUM/AVG/COUNT), SQL Injection, Brute-Force &amp; Lạm dụng quyền</div>
              </div>
            </div>
            <div class="card-tools">
              <input type="text" id="tab-alert-search" class="search-input" placeholder="🔍 Lọc User, Loại tấn công, SQL..." oninput="renderDedicatedAlerts()" />
              <div class="filter-group">
                <button class="filter-btn active" onclick="filterSev('ALL', this)">Tất cả</button>
                <button class="filter-btn" onclick="filterSev('CRITICAL', this)">Critical</button>
                <button class="filter-btn" onclick="filterSev('HIGH', this)">High</button>
                <button class="filter-btn" onclick="filterSev('MEDIUM', this)">Medium</button>
              </div>
              <button class="btn btn-sm btn-danger-outline" onclick="clearAlerts('ids')" title="Xóa toàn bộ cảnh báo IDS">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                <span>Xóa cảnh báo</span>
              </button>
            </div>
          </div>
          <div class="table-wrap" id="dedicated-alerts-container"></div>
        </section>
      </div>

      <!-- ====================================================================
           TAB 3: BẪY FGA & HONEYTOKEN (FGA ONLY)
           ==================================================================== -->
      <div class="tab-view" id="tab-fga">
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon purple">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polygon points="12 2 2 7 12 12 22 7 12 2"/>
                  <polyline points="2 17 12 22 22 17"/>
                  <polyline points="2 12 12 17 22 12"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Kiểm toán Mịn (DBMS_FGA) &amp; Bẫy Dữ liệu Honeytoken</div>
                <div class="card-subtitle-text">Giám sát 2 chính sách: FGA_HONEYTOKEN_TRAP (bẫy manv='NV_TRAP') &amp; FGA_HIGH_SALARY_ACCESS (lương &gt;= 1000)</div>
              </div>
            </div>
          </div>
          <div class="table-wrap" id="dedicated-fga-container"></div>
        </section>
      </div>

      <!-- ====================================================================
           TAB 4: TRIGGER CHẶN TỨC THỜI (TRIGGERS ONLY)
           ==================================================================== -->
      <div class="tab-view" id="tab-triggers">
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon yellow">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Hành vi bị chặn tức thời bởi Database Trigger (Autonomous Transaction)</div>
                <div class="card-subtitle-text">Ghi nhận từ SYS.IDS_TRIGGER_ALERTS: Ngăn chặn xóa nhân viên và tăng lương trái phép &gt; 50%</div>
              </div>
            </div>
            <div class="card-tools">
              <button class="btn btn-sm btn-warning-outline" onclick="clearAlerts('triggers')" title="Xóa nhật ký Trigger">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                <span>Xóa log Trigger</span>
              </button>
            </div>
          </div>
          <div class="table-wrap" id="dedicated-triggers-container"></div>
        </section>
      </div>

      <!-- ====================================================================
           TAB 5: NHẬT KÝ KIỂM TOÁN (AUDIT LOG ONLY)
           ==================================================================== -->
      <div class="tab-view" id="tab-audit">
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
                  <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Nhật ký Kiểm toán Thời gian thực (UNIFIED_AUDIT_TRAIL)</div>
                <div class="card-subtitle-text">Truy vấn chi tiết câu lệnh SQL, Return Code, OS User, Host và Client Application</div>
              </div>
            </div>
            <div class="card-tools">
              <input type="text" id="audit-search" class="search-input" placeholder="🔍 Lọc User, Policy, Client, SQL..." oninput="renderAuditTable()" />
            </div>
          </div>
          <div class="table-wrap" id="dedicated-audit-container"></div>
        </section>
      </div>

      <!-- ====================================================================
           TAB 6: TÀI KHOẢN & DỮ LIỆU NV (USERS & SYS.NV ONLY)
           ==================================================================== -->
      <div class="tab-view" id="tab-users">
        <!-- Quản lý tài khoản User -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                  <circle cx="12" cy="7" r="4"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Quản lý Quyền Tài khoản Thực nghiệm &amp; Điều khiển Phản ứng</div>
                <div class="card-subtitle-text">Kiểm soát trạng thái khóa tài khoản và chế độ quyền DML (Read-Only / Full DML) trên SYS.NV</div>
              </div>
            </div>
          </div>
          <div class="table-wrap" id="dedicated-users-container"></div>
        </section>

        <!-- Dữ liệu bảng SYS.NV & Bẫy Honeytoken -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="2" y="7" width="20" height="14" rx="2" ry="2"/>
                  <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Dữ liệu Bảng Nhạy cảm SYS.NV &amp; Bản ghi Bẫy Honeytoken (NV_TRAP)</div>
                <div class="card-subtitle-text">Bảo vệ đa tầng: Trigger TRG_PROTECT_NV + FGA_HONEYTOKEN_TRAP + Unified Audit</div>
              </div>
            </div>
          </div>
          <div class="table-wrap" id="dedicated-employees-container"></div>
        </section>
      </div>

      <!-- ====================================================================
           TAB 7: PHẢN ỨNG ĐA CẤP (GRADUATED ACTIVE IPS CONTROLS)
           ==================================================================== -->
      <div class="tab-view" id="tab-ips">
        <!-- Cấu hình và công tắc IPS -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-header-icon purple">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
              </div>
              <div>
                <div class="card-title-text">Trung tâm Điều khiển Phản ứng Đa cấp (Graduated Active Response &amp; IPS)</div>
                <div class="card-subtitle-text">Cấu hình tự động hóa phân cấp xử lý vi phạm dựa trên Risk Score thời gian thực</div>
              </div>
            </div>
            <div class="card-tools">
              <button class="btn btn-sm btn-warning-outline" onclick="clearAlerts('all')" title="Đặt lại toàn bộ Risk Score về 0">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                <span>Reset Risk Score &amp; Lịch sử</span>
              </button>
            </div>
          </div>

          <div style="padding:16px 18px;">
            <div class="switch-row">
              <div>
                <div style="font-weight:700;color:var(--text-primary);font-size:12.5px;">Tự động Phản ứng theo Risk Score (Graduated IPS)</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Tự động hạ quyền Read-Only (L2: 50-79) hoặc Khóa tài khoản &amp; ngắt kết nối (L3: &gt;=80)</div>
              </div>
              <label class="switch">
                <input type="checkbox" id="ips-toggle" checked onchange="toggleAutoResponse(this.checked)" />
                <span class="slider"></span>
              </label>
            </div>

            <div class="switch-row" style="margin-bottom:0;">
              <div>
                <div style="font-weight:700;color:var(--text-primary);font-size:12.5px;">Tự động làm mới dữ liệu chu kỳ 5 giây</div>
                <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Tự động đồng bộ các vi phạm và trạng thái tài khoản thời gian thực từ Oracle</div>
              </div>
              <label class="switch">
                <input type="checkbox" id="autorefresh-toggle" checked onchange="toggleAutoRefresh(this.checked)" />
                <span class="slider"></span>
              </label>
            </div>
          </div>
        </section>

        <!-- Bảng hiển thị Ma trận cấp độ rủi ro IPS -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-title-text">Ma trận Phân cấp Bảo vệ (IPS Defense Level Matrix)</div>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Cấp độ</th>
                  <th>Phạm vi Risk Score</th>
                  <th>Hành vi Kích hoạt</th>
                  <th>Biện pháp Can thiệp Tự động</th>
                  <th>Khả năng thao tác CSDL</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><span class="badge badge-success">Level 0: Normal</span></td>
                  <td class="mono">0 – 19</td>
                  <td>Hoạt động bình thường, đúng nghiệp vụ</td>
                  <td>Ghi nhận kiểm toán tiêu chuẩn</td>
                  <td>Đầy đủ quyền SELECT, INSERT, UPDATE, DELETE</td>
                </tr>
                <tr>
                  <td><span class="badge badge-medium">Level 1: Warning</span></td>
                  <td class="mono">20 – 49</td>
                  <td>Truy cập ngoài giờ, thử mật khẩu sai 1-2 lần</td>
                  <td>Cảnh báo SOC, tăng tần suất theo dõi</td>
                  <td>Duy trì quyền hiện tại</td>
                </tr>
                <tr>
                  <td><span class="badge badge-high">Level 2: Containment</span></td>
                  <td class="mono">50 – 79</td>
                  <td>Thống kê lương cao (SUM/AVG), quét schema</td>
                  <td>Thu hồi quyền DML (REVOKE INSERT, UPDATE, DELETE)</td>
                  <td>Chỉ cho phép đọc (READ-ONLY)</td>
                </tr>
                <tr>
                  <td><span class="badge badge-critical">Level 3: Isolation</span></td>
                  <td class="mono">80 – 100</td>
                  <td>Chạm bẫy Honeytoken (NV_TRAP), SQL Injection, Brute-Force</td>
                  <td>Khóa tài khoản (ALTER USER LOCK) &amp; Ngắt phiên kết nối (KILL SESSION)</td>
                  <td>Toàn bộ kết nối bị từ chối và chặn đứng</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Bảng Trạng thái User trong IPS -->
        <section class="card">
          <div class="card-header">
            <div class="card-title-left">
              <div class="card-title-text">Trạng thái Cách ly &amp; Phản ứng Thực tế Từng User</div>
            </div>
          </div>
          <div class="table-wrap" id="ips-users-container"></div>
        </section>
      </div>

    </main>
  </div>

  <!-- ==========================================================================
       INSPECTION MODAL
       ========================================================================== -->
  <div class="modal-backdrop" id="audit-modal" onclick="if(event.target===this) closeAuditModal()">
    <div class="modal-box">
      <div class="modal-header">
        <div class="modal-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:17px;height:17px;color:var(--accent-blue);">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
          </svg>
          <span id="modal-title-text">Chi tiết Bản ghi Kiểm toán &amp; Ngữ cảnh</span>
        </div>
        <button class="modal-close" onclick="closeAuditModal()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
      <div class="modal-body" id="audit-modal-body"></div>
      <div class="modal-footer">
        <button class="btn btn-sm" onclick="copyModalSql()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
          <span>Sao chép SQL</span>
        </button>
        <button class="btn btn-sm btn-primary" onclick="closeAuditModal()">Đóng</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification Container -->
  <div class="toast-container" id="toast-container"></div>

  <!-- ==========================================================================
       JAVASCRIPT CLIENT APPLICATION LOGIC
       100% Functionality Preserved • Zero Duplication Across Tabs
       ========================================================================== -->
  <script>
    let cachedData = {};
    let cachedAuditLogs = [];
    let currentModalSql = '';
    let autoRefreshTimer = null;
    let currentAlertFilter = 'ALL';

    const SVG_ICONS = {
      lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
      unlock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`,
      shieldOff: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"/><path d="M4.73 4.73L4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
      shieldCheck: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
      check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
      alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
      trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>`,
      eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`
    };

    function escapeHtml(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function getRiskColor(score) {
      const s = Number(score || 0);
      if (s >= 80) return '#ef4444';
      if (s >= 50) return '#f97316';
      if (s >= 20) return '#eab308';
      return '#10b981';
    }

    function getSeverityBadge(sev) {
      const s = String(sev || '').toUpperCase();
      if (s === 'CRITICAL') return '<span class="badge badge-critical">▲ CRITICAL</span>';
      if (s === 'HIGH') return '<span class="badge badge-high">▲ HIGH</span>';
      if (s === 'MEDIUM') return '<span class="badge badge-medium">▲ MEDIUM</span>';
      return '<span class="badge badge-success">▲ LOW</span>';
    }

    function getIpsLevelBadge(lvl, label) {
      const l = Number(lvl || 0);
      const text = escapeHtml(label || `Level ${l}`);
      if (l >= 3) return `<span class="badge badge-critical">${text}</span>`;
      if (l === 2) return `<span class="badge badge-high">${text}</span>`;
      if (l === 1) return `<span class="badge badge-medium">${text}</span>`;
      return `<span class="badge badge-success">${text}</span>`;
    }

    function renderRiskBar(score) {
      const s = Math.max(0, Math.min(100, Number(score || 0)));
      const color = getRiskColor(s);
      return `
        <div class="risk-inline">
          <span class="risk-score-text" style="color:${color}">${s}/100</span>
          <div class="risk-bar-track">
            <div class="risk-bar-prog" style="width:${s}%;background:${color}"></div>
          </div>
        </div>
      `;
    }

    function showToast(msg, type = 'success') {
      const container = document.getElementById('toast-container');
      const el = document.createElement('div');
      el.className = `toast ${type}`;
      el.innerHTML = `${type === 'success' ? SVG_ICONS.check : SVG_ICONS.alert}<span>${escapeHtml(msg)}</span>`;
      container.appendChild(el);
      setTimeout(() => el.remove(), 3500);
    }

    /* Tab Switching Functionality */
    function switchTab(tabId, navEl) {
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      if (navEl) {
        navEl.classList.add('active');
      } else {
        // Find matching item by onclick
        const match = Array.from(document.querySelectorAll('.nav-item')).find(el => el.getAttribute('onclick')?.includes(`'${tabId}'`));
        if (match) match.classList.add('active');
      }

      document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
      const activeView = document.getElementById(`tab-${tabId}`);
      if (activeView) activeView.classList.add('active');

      const heading = document.getElementById('topbar-heading');
      const subheading = document.getElementById('topbar-subheading');

      if (tabId === 'home') {
        heading.textContent = 'Trung tâm Giám sát An ninh CSDL';
        subheading.textContent = 'Oracle 23ai DB-IDS • Honeytoken Canary • Thống kê & Phòng thủ thông minh';
      } else if (tabId === 'alerts') {
        heading.textContent = 'Cảnh báo Xâm nhập Đa chiều & Chấm điểm Rủi ro (Risk Scoring)';
        subheading.textContent = 'Phát hiện Honeytoken Trap, Thống kê suy diễn (SUM/AVG/COUNT), SQL Injection & Brute-Force';
      } else if (tabId === 'fga') {
        heading.textContent = 'Giám sát Kiểm toán Mịn (DBMS_FGA) & Bẫy Dữ liệu Honeytoken';
        subheading.textContent = 'Policies: FGA_HONEYTOKEN_TRAP (manv="NV_TRAP") & FGA_HIGH_SALARY_ACCESS (lương >= 1000)';
      } else if (tabId === 'triggers') {
        heading.textContent = 'Hành vi bị chặn tức thời bởi Database Trigger';
        subheading.textContent = 'Trigger Autonomous Transaction - Ngăn chặn xóa nhân viên & Chặn tăng lương trái phép > 50%';
      } else if (tabId === 'audit') {
        heading.textContent = 'Nhật ký Kiểm toán Thời gian thực (UNIFIED_AUDIT_TRAIL)';
        subheading.textContent = 'Truy vấn chi tiết câu lệnh SQL, Return Code, OS User, Host và Client Application';
      } else if (tabId === 'users') {
        heading.textContent = 'Quản lý Tài khoản & Dữ liệu Bảng Nhạy cảm (SYS.NV)';
        subheading.textContent = 'Kiểm soát quyền truy cập User thực nghiệm và bản ghi bẫy Honeytoken';
      } else if (tabId === 'ips') {
        heading.textContent = 'Phản ứng Đa cấp Tự động (Graduated Active Response & IPS)';
        subheading.textContent = 'Cấu hình tự động hóa: Level 0 Normal → Level 1 Warning → Level 2 Read-Only → Level 3 Isolation';
      }
    }

    async function refreshData(flush = false) {
      const svg = document.getElementById('refresh-svg');
      svg.classList.add('spin');
      try {
        const res = await fetch(`/api/data?flush=${flush ? '1' : '0'}`);
        const data = await res.json();
        cachedData = data;
        renderDashboard(data);
        if (flush && data.ok) {
          showToast('Đã đồng bộ và làm mới dữ liệu Unified Audit & FGA!');
        }
      } catch (err) {
        showToast('Không thể kết nối máy chủ', 'error');
      } finally {
        setTimeout(() => svg.classList.remove('spin'), 350);
      }
    }

    function renderDashboard(data) {
      const connDot = document.getElementById('conn-dot');
      const connText = document.getElementById('conn-text');

      if (!data.ok) {
        connDot.classList.add('offline');
        connText.textContent = 'Mất kết nối Oracle';
        return;
      }
      connDot.classList.remove('offline');
      connText.textContent = `${data.dsn || 'FREEPDB1'}`;

      const m = data.metrics || {};
      document.getElementById('kpi-audit').textContent = m.audit_count ?? 0;
      document.getElementById('kpi-alerts').textContent = m.alert_count ?? 0;
      document.getElementById('kpi-triggers').textContent = m.trigger_count ?? 0;
      document.getElementById('kpi-locked').textContent = `${m.max_risk ?? 0} / 100`;
      document.getElementById('kpi-ips-sub').textContent = `Khóa (L3): ${m.locked_count ?? 0} | Read-Only (L2): ${m.readonly_count ?? 0}`;

      // In alerts tab
      document.getElementById('alerts-kpi-audit').textContent = m.audit_count ?? 0;
      document.getElementById('alerts-kpi-alerts').textContent = m.alert_count ?? 0;
      document.getElementById('alerts-kpi-triggers').textContent = m.trigger_count ?? 0;
      document.getElementById('alerts-kpi-locked').textContent = `${m.max_risk ?? 0} / 100`;
      document.getElementById('alerts-kpi-ips-sub').textContent = `Khóa (L3): ${m.locked_count ?? 0} | Read-Only (L2): ${m.readonly_count ?? 0}`;

      document.getElementById('nav-alert-count').textContent = m.alert_count ?? 0;
      document.getElementById('ips-toggle').checked = !!data.auto_response;

      if (data.auto_locked && data.auto_locked.length > 0) {
        showToast(`[Level 3] Đã tự động KHÓA & ngắt kết nối: ${data.auto_locked.join(', ')}`, 'error');
      }
      if (data.auto_revoked && data.auto_revoked.length > 0) {
        showToast(`[Level 2] Đã tự động hạ quyền Read-Only: ${data.auto_revoked.join(', ')}`, 'error');
      }

      // Render views
      renderHomeAlerts();
      renderHomePreviews();
      renderDedicatedAlerts();
      renderDedicatedFga();
      renderDedicatedTriggers();
      renderDedicatedUsers();
      renderDedicatedEmployees();
      renderIpsView();

      cachedAuditLogs = data.audit_logs || [];
      renderAuditTable();
    }

    /* TAB 1: HOME OVERVIEW RENDERS */
    function renderHomeAlerts() {
      const container = document.getElementById('home-alerts-container');
      const alerts = cachedData.alerts || [];
      const query = (document.getElementById('home-alert-search')?.value || '').toLowerCase().trim();

      const filtered = alerts.filter(a => {
        if (!query) return true;
        return (
          String(a.user || '').toLowerCase().includes(query) ||
          String(a.attack_type || '').toLowerCase().includes(query) ||
          String(a.details || '').toLowerCase().includes(query) ||
          String(a.context || '').toLowerCase().includes(query)
        );
      });

      if (!filtered.length) {
        container.innerHTML = `
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            <div>Hệ thống an toàn (Risk Score = 0). Không có cảnh báo xâm nhập nào.</div>
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Mức độ</th>
              <th>Risk Score</th>
              <th>Mức phản ứng (IPS)</th>
              <th>Thời gian</th>
              <th>User</th>
              <th>Loại tấn công / Bất thường</th>
              <th>Ngữ cảnh (Client / Host)</th>
              <th style="text-align:right">Thao tác</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map((a, idx) => `
              <tr class="clickable-row" onclick="openAlertModal(${idx})">
                <td>${getSeverityBadge(a.severity)}</td>
                <td>${renderRiskBar(a.risk_score)}</td>
                <td>${getIpsLevelBadge(a.response_level, a.response_label)}</td>
                <td class="mono">${escapeHtml(a.time)}</td>
                <td><strong>${escapeHtml(a.user)}</strong></td>
                <td>${escapeHtml(a.attack_type)}</td>
                <td class="mono" style="color:var(--text-secondary);font-size:11px;">${escapeHtml(a.context || '—')}</td>
                <td style="text-align:right" onclick="event.stopPropagation()">
                  <button class="btn btn-sm btn-danger-outline" onclick="dismissSingleIdsAlert(${idx})" title="Xóa cảnh báo này">
                    ${SVG_ICONS.trash}
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderHomePreviews() {
      // Compact FGA preview for Overview
      const fgaContainer = document.getElementById('home-fga-container');
      const fgaEvents = (cachedData.fga_events || []).slice(0, 5);
      if (!fgaEvents.length) {
        fgaContainer.innerHTML = `<div class="empty-state" style="padding:18px;">Chưa có sự kiện bẫy FGA nào.</div>`;
      } else {
        fgaContainer.innerHTML = `
          <table>
            <thead>
              <tr>
                <th>Thời gian</th>
                <th>User</th>
                <th>Chính sách FGA</th>
                <th>Ngữ cảnh (Client)</th>
              </tr>
            </thead>
            <tbody>
              ${fgaEvents.map(r => `
                <tr class="${String(r.FGA_POLICY_NAME).includes('HONEYTOKEN') ? 'honeytoken-row' : ''}">
                  <td class="mono">${escapeHtml(r.EVENT_TIMESTAMP)}</td>
                  <td><strong>${escapeHtml(r.DBUSERNAME)}</strong></td>
                  <td><span class="badge ${String(r.FGA_POLICY_NAME).includes('HONEYTOKEN') ? 'badge-critical' : 'badge-neutral'}">${escapeHtml(r.FGA_POLICY_NAME || 'FGA')}</span></td>
                  <td class="mono" style="font-size:11px;color:var(--text-muted);">${escapeHtml(r.CLIENT_PROGRAM_NAME || 'SQL Developer')}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      }

      // Compact Trigger preview for Overview
      const trigContainer = document.getElementById('home-triggers-container');
      const triggers = (cachedData.triggers || []).slice(0, 5);
      if (!triggers.length) {
        trigContainer.innerHTML = `<div class="empty-state" style="padding:18px;">Chưa có vi phạm nào bị Trigger chặn.</div>`;
      } else {
        trigContainer.innerHTML = `
          <table>
            <thead>
              <tr>
                <th>Thời gian</th>
                <th>User</th>
                <th>Loại vi phạm</th>
                <th>Chi tiết ngắn gọn</th>
              </tr>
            </thead>
            <tbody>
              ${triggers.map(t => `
                <tr>
                  <td class="mono">${escapeHtml(t.EVENT_TIME)}</td>
                  <td><strong>${escapeHtml(t.DB_USER)}</strong></td>
                  <td><span class="badge badge-high">${escapeHtml(t.ATTACK_TYPE)}</span></td>
                  <td style="color:var(--text-secondary);">${escapeHtml(t.DETAILS)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      }
    }

    /* TAB 2: DEDICATED ALERTS TAB */
    function filterSev(sev, btnEl) {
      currentAlertFilter = sev;
      if (btnEl) {
        btnEl.parentElement.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btnEl.classList.add('active');
      }
      renderDedicatedAlerts();
    }

    function renderDedicatedAlerts() {
      const container = document.getElementById('dedicated-alerts-container');
      const alerts = cachedData.alerts || [];
      const query = (document.getElementById('tab-alert-search')?.value || '').toLowerCase().trim();

      const filtered = alerts.filter(a => {
        if (currentAlertFilter !== 'ALL' && String(a.severity || '').toUpperCase() !== currentAlertFilter) {
          return false;
        }
        if (query) {
          const match = (
            String(a.user || '').toLowerCase().includes(query) ||
            String(a.attack_type || '').toLowerCase().includes(query) ||
            String(a.details || '').toLowerCase().includes(query) ||
            String(a.context || '').toLowerCase().includes(query)
          );
          if (!match) return false;
        }
        return true;
      });

      if (!filtered.length) {
        container.innerHTML = `
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            <div>Không có cảnh báo nào phù hợp với bộ lọc hiện tại.</div>
          </div>
        `;
        return;
      }

      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Mức độ</th>
              <th>Risk Score</th>
              <th>Mức phản ứng (IPS)</th>
              <th>Thời gian</th>
              <th>User</th>
              <th>Loại tấn công / Bất thường</th>
              <th>Ngữ cảnh (Client / Host)</th>
              <th>Chi tiết / Câu lệnh SQL</th>
              <th style="text-align:right">Thao tác</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map((a, idx) => `
              <tr class="clickable-row" onclick="openAlertModal(${idx})">
                <td>${getSeverityBadge(a.severity)}</td>
                <td>${renderRiskBar(a.risk_score)}</td>
                <td>${getIpsLevelBadge(a.response_level, a.response_label)}</td>
                <td class="mono">${escapeHtml(a.time)}</td>
                <td><strong>${escapeHtml(a.user)}</strong></td>
                <td>${escapeHtml(a.attack_type)}</td>
                <td class="mono" style="font-size:11px;color:var(--text-secondary);">${escapeHtml(a.context || '—')}</td>
                <td><span class="sql-code" title="${escapeHtml(a.details)}">${escapeHtml(a.details)}</span></td>
                <td style="text-align:right" onclick="event.stopPropagation()">
                  <div style="display:inline-flex;gap:5px;">
                    <button class="btn btn-sm" onclick="openAlertModal(${idx})" title="Xem chi tiết">
                      ${SVG_ICONS.eye}
                    </button>
                    <button class="btn btn-sm btn-danger-outline" onclick="dismissSingleIdsAlert(${idx})" title="Xóa cảnh báo">
                      ${SVG_ICONS.trash}
                    </button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
      window._currentAlerts = filtered;
    }

    /* TAB 3: DEDICATED FGA TAB */
    function renderDedicatedFga() {
      const container = document.getElementById('dedicated-fga-container');
      const rows = cachedData.fga_events || [];
      if (!rows.length) {
        container.innerHTML = `<div class="empty-state">Chưa có sự kiện nào kích hoạt bẫy FGA_HONEYTOKEN_TRAP hoặc FGA_HIGH_SALARY_ACCESS.</div>`;
        return;
      }
      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Thời gian</th>
              <th>User</th>
              <th>Chính sách FGA (FGA_POLICY_NAME)</th>
              <th>Ngữ cảnh (Client / Host)</th>
              <th>Câu lệnh kích hoạt (SQL_TEXT)</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(r => {
              const isTrap = String(r.FGA_POLICY_NAME).includes('HONEYTOKEN');
              const ctx = `${r.CLIENT_PROGRAM_NAME || 'Unknown'} (${r.OS_USERNAME || 'os'}@${r.USERHOST || 'host'})`;
              return `
                <tr class="${isTrap ? 'honeytoken-row' : ''}">
                  <td class="mono">${escapeHtml(r.EVENT_TIMESTAMP)}</td>
                  <td><strong>${escapeHtml(r.DBUSERNAME)}</strong></td>
                  <td>
                    <span class="badge ${isTrap ? 'badge-critical' : 'badge-neutral'}">
                      ${escapeHtml(r.FGA_POLICY_NAME || 'FineGrainedAudit')}
                    </span>
                  </td>
                  <td class="mono" style="font-size:11px;color:var(--text-secondary);">${escapeHtml(ctx)}</td>
                  <td><span class="sql-code" title="${escapeHtml(r.SQL_TEXT)}">${escapeHtml(r.SQL_TEXT || r.ACTION_NAME)}</span></td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;
    }

    /* TAB 4: DEDICATED TRIGGERS TAB */
    function renderDedicatedTriggers() {
      const container = document.getElementById('dedicated-triggers-container');
      const rows = cachedData.triggers || [];
      if (!rows.length) {
        container.innerHTML = `<div class="empty-state">Chưa có vi phạm thao tác dữ liệu nào bị Database Trigger chặn.</div>`;
        return;
      }
      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Thời gian</th>
              <th>User</th>
              <th>Loại vi phạm</th>
              <th>Chi tiết ngăn chặn</th>
              <th style="text-align:right">Thao tác</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(t => `
              <tr>
                <td class="mono">${escapeHtml(t.EVENT_TIME)}</td>
                <td><strong>${escapeHtml(t.DB_USER)}</strong></td>
                <td><span class="badge badge-high">${escapeHtml(t.ATTACK_TYPE)}</span></td>
                <td>${escapeHtml(t.DETAILS)}</td>
                <td style="text-align:right">
                  <button class="btn btn-sm btn-danger-outline" onclick="clearSingleTrigger(${Number(t.ALERT_ID)})" title="Xóa dòng này">
                    ${SVG_ICONS.trash}
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    /* TAB 5: DEDICATED AUDIT LOG TAB */
    function renderAuditTable() {
      const container = document.getElementById('dedicated-audit-container');
      const keyword = (document.getElementById('audit-search')?.value || '').toLowerCase().trim();
      const filtered = cachedAuditLogs.filter(row => {
        if (!keyword) return true;
        return (
          String(row.DBUSERNAME || '').toLowerCase().includes(keyword) ||
          String(row.ACTION_NAME || '').toLowerCase().includes(keyword) ||
          String(row.OBJECT_NAME || '').toLowerCase().includes(keyword) ||
          String(row.FGA_POLICY_NAME || '').toLowerCase().includes(keyword) ||
          String(row.CLIENT_PROGRAM_NAME || '').toLowerCase().includes(keyword) ||
          String(row.USERHOST || '').toLowerCase().includes(keyword) ||
          String(row.SQL_TEXT || '').toLowerCase().includes(keyword) ||
          String(row.RETURN_CODE || '').toLowerCase().includes(keyword)
        );
      });

      if (!filtered.length) {
        container.innerHTML = `<div class="empty-state">Không có bản ghi kiểm toán nào khớp bộ lọc.</div>`;
        return;
      }

      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Thời gian</th>
              <th>DB User</th>
              <th>Loại Audit / Policy</th>
              <th>Action</th>
              <th>Đối tượng</th>
              <th>Ngữ cảnh (Client / Host)</th>
              <th>Câu lệnh SQL</th>
              <th>Mã trả về</th>
              <th style="text-align:right">Chi tiết</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map((r, idx) => {
              const code = Number(r.RETURN_CODE || 0);
              const badgeClass = code === 0 ? 'badge-success' : 'badge-critical';
              const isFga = String(r.AUDIT_TYPE) === 'FineGrainedAudit' || !!r.FGA_POLICY_NAME;
              const objFull = r.OBJECT_SCHEMA && r.OBJECT_NAME ? `${r.OBJECT_SCHEMA}.${r.OBJECT_NAME}` : (r.OBJECT_NAME || '—');
              const ctx = `${r.CLIENT_PROGRAM_NAME || '—'} @ ${r.USERHOST || '—'}`;
              return `
                <tr class="clickable-row ${String(r.FGA_POLICY_NAME).includes('HONEYTOKEN') ? 'honeytoken-row' : ''}" onclick="openAuditModal(${idx})">
                  <td class="mono">${escapeHtml(r.EVENT_TIMESTAMP)}</td>
                  <td><strong>${escapeHtml(r.DBUSERNAME)}</strong></td>
                  <td><span class="badge ${isFga ? 'badge-medium' : 'badge-neutral'}">${escapeHtml(r.FGA_POLICY_NAME || r.AUDIT_TYPE || 'Standard')}</span></td>
                  <td><span class="badge badge-neutral">${escapeHtml(r.ACTION_NAME)}</span></td>
                  <td class="mono">${escapeHtml(objFull)}</td>
                  <td class="mono" style="font-size:11px;color:var(--text-secondary);">${escapeHtml(ctx)}</td>
                  <td>${r.SQL_TEXT ? `<span class="sql-code" title="${escapeHtml(r.SQL_TEXT)}">${escapeHtml(r.SQL_TEXT)}</span>` : '<span style="color:var(--text-muted)">—</span>'}</td>
                  <td><span class="badge ${badgeClass} mono">${code === 0 ? '0 (OK)' : 'ORA-' + code}</span></td>
                  <td style="text-align:right" onclick="event.stopPropagation(); openAuditModal(${idx});">
                    <button class="btn btn-sm">${SVG_ICONS.eye}<span>Xem</span></button>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;
      window._filteredAudit = filtered;
    }

    /* TAB 6: DEDICATED USERS & EMPLOYEES TAB */
    function renderDedicatedUsers() {
      const container = document.getElementById('dedicated-users-container');
      const users = cachedData.users || [];
      if (!users.length) {
        container.innerHTML = `<div class="empty-state">Chưa có thông tin User.</div>`;
        return;
      }
      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Tài khoản</th>
              <th>Trạng thái Account</th>
              <th>Chế độ Quyền (SYS.NV)</th>
              <th>Risk Score</th>
              <th>Mức Phản ứng IPS</th>
              <th>Thời điểm khóa</th>
              <th style="text-align:right">Điều khiển Cách ly (Admin Controls)</th>
            </tr>
          </thead>
          <tbody>
            ${users.map(u => {
              const isLocked = String(u.ACCOUNT_STATUS).toUpperCase().includes('LOCK');
              const isReadOnly = String(u.DML_STATUS).toUpperCase() === 'READ-ONLY';
              return `
                <tr>
                  <td><strong>${escapeHtml(u.USERNAME)}</strong></td>
                  <td><span class="badge ${isLocked ? 'badge-critical' : 'badge-success'}">${isLocked ? SVG_ICONS.lock : SVG_ICONS.unlock} ${escapeHtml(u.ACCOUNT_STATUS)}</span></td>
                  <td><span class="badge ${isReadOnly ? 'badge-high' : 'badge-success'}">${isReadOnly ? 'READ-ONLY' : 'FULL DML'}</span></td>
                  <td>${renderRiskBar(u.RISK_SCORE)}</td>
                  <td>${getIpsLevelBadge(u.RESPONSE_LEVEL, u.RESPONSE_LABEL)}</td>
                  <td class="mono">${escapeHtml(u.LOCK_DATE || '—')}</td>
                  <td style="text-align:right">
                    <div style="display:inline-flex;gap:5px;">
                      ${isReadOnly
                        ? `<button class="btn btn-sm" onclick="userAction('${escapeHtml(u.USERNAME)}', 'grant_dml')" title="Khôi phục quyền SELECT, INSERT, UPDATE, DELETE">${SVG_ICONS.shieldCheck}<span>Khôi phục DML</span></button>`
                        : `<button class="btn btn-sm btn-warning-outline" onclick="userAction('${escapeHtml(u.USERNAME)}', 'revoke_dml')" title="Thu hồi quyền INSERT, UPDATE, DELETE">${SVG_ICONS.shieldOff}<span>Read-Only</span></button>`
                      }
                      ${isLocked
                        ? `<button class="btn btn-sm" style="color:#6ee7b7;border-color:var(--safe-border);" onclick="userAction('${escapeHtml(u.USERNAME)}', 'unlock')">${SVG_ICONS.unlock}<span>Mở khóa</span></button>`
                        : `<button class="btn btn-sm btn-danger-outline" onclick="userAction('${escapeHtml(u.USERNAME)}', 'lock')">${SVG_ICONS.lock}<span>Khóa &amp; Kill</span></button>`
                      }
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;
    }

    function renderDedicatedEmployees() {
      const container = document.getElementById('dedicated-employees-container');
      const rows = cachedData.employees || [];
      if (!rows.length) {
        container.innerHTML = `<div class="empty-state">Chưa có dữ liệu bảng SYS.NV.</div>`;
        return;
      }
      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Mã NV</th>
              <th>Phân loại Bản ghi</th>
              <th>Họ và Tên</th>
              <th>Lương</th>
              <th>Giới tính</th>
              <th>CMND / CCCD</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(r => {
              const isTrap = String(r.MANV).toUpperCase() === 'NV_TRAP';
              return `
                <tr class="${isTrap ? 'honeytoken-row' : ''}">
                  <td class="mono"><strong>${escapeHtml(r.MANV)}</strong></td>
                  <td>${isTrap ? `<span class="badge badge-critical">${SVG_ICONS.alert} HONEYTOKEN CANARY TRAP</span>` : `<span class="badge badge-neutral">Bản ghi Nghiệp vụ</span>`}</td>
                  <td><strong>${escapeHtml(r.HOTEN)}</strong></td>
                  <td class="mono" style="color:${isTrap ? '#ef4444' : '#10b981'};font-weight:700;">${escapeHtml(r.LUONG)}</td>
                  <td>${escapeHtml(r.GIOITINH)}</td>
                  <td class="mono">${escapeHtml(r.CMND)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;
    }

    /* TAB 7: DEDICATED IPS TAB */
    function renderIpsView() {
      const container = document.getElementById('ips-users-container');
      const users = cachedData.users || [];
      if (!users.length) return;
      container.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Tài khoản</th>
              <th>Risk Score</th>
              <th>Cấp độ Phản ứng Hiện tại</th>
              <th>Chế độ Quyền</th>
              <th>Trạng thái Tài khoản</th>
              <th style="text-align:right">Hành động Phản ứng Thủ công</th>
            </tr>
          </thead>
          <tbody>
            ${users.map(u => {
              const isLocked = String(u.ACCOUNT_STATUS).toUpperCase().includes('LOCK');
              const isReadOnly = String(u.DML_STATUS).toUpperCase() === 'READ-ONLY';
              return `
                <tr>
                  <td><strong>${escapeHtml(u.USERNAME)}</strong></td>
                  <td>${renderRiskBar(u.RISK_SCORE)}</td>
                  <td>${getIpsLevelBadge(u.RESPONSE_LEVEL, u.RESPONSE_LABEL)}</td>
                  <td><span class="badge ${isReadOnly ? 'badge-high' : 'badge-success'}">${isReadOnly ? 'READ-ONLY' : 'FULL DML'}</span></td>
                  <td><span class="badge ${isLocked ? 'badge-critical' : 'badge-success'}">${escapeHtml(u.ACCOUNT_STATUS)}</span></td>
                  <td style="text-align:right">
                    <div style="display:inline-flex;gap:6px;">
                      ${isReadOnly
                        ? `<button class="btn btn-sm" onclick="userAction('${escapeHtml(u.USERNAME)}', 'grant_dml')">${SVG_ICONS.shieldCheck}<span>Khôi phục DML</span></button>`
                        : `<button class="btn btn-sm btn-warning-outline" onclick="userAction('${escapeHtml(u.USERNAME)}', 'revoke_dml')">${SVG_ICONS.shieldOff}<span>Read-Only</span></button>`
                      }
                      ${isLocked
                        ? `<button class="btn btn-sm" style="color:#6ee7b7;border-color:var(--safe-border);" onclick="userAction('${escapeHtml(u.USERNAME)}', 'unlock')">Mở khóa User</button>`
                        : `<button class="btn btn-sm btn-danger-outline" onclick="userAction('${escapeHtml(u.USERNAME)}', 'lock')">Khóa L3 (Isolation)</button>`
                      }
                    </div>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      `;
    }

    /* MODAL FUNCTIONS */
    function openAlertModal(idx) {
      const a = (window._currentAlerts || cachedData.alerts || [])[idx];
      if (!a) return;
      currentModalSql = String(a.details || '');
      document.getElementById('modal-title-text').textContent = 'Chi tiết Cảnh báo Xâm nhập Đa chiều (IDS Detection Alert)';
      const body = document.getElementById('audit-modal-body');
      body.innerHTML = `
        <div class="detail-grid">
          <div class="detail-item">
            <div class="detail-label">Thời gian phát hiện</div>
            <div class="detail-val mono">${escapeHtml(a.time)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Tài khoản CSDL vi phạm</div>
            <div class="detail-val"><strong>${escapeHtml(a.user)}</strong></div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Mức độ cảnh báo (Severity)</div>
            <div class="detail-val">${getSeverityBadge(a.severity)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Mức phản ứng IPS</div>
            <div class="detail-val">${getIpsLevelBadge(a.response_level, a.response_label)}</div>
          </div>
          <div class="detail-item" style="grid-column:span 2;">
            <div class="detail-label">Loại tấn công / Hành vi bất thường</div>
            <div class="detail-val" style="color:#fdba74;font-weight:700;">${escapeHtml(a.attack_type)}</div>
          </div>
          <div class="detail-item" style="grid-column:span 2;">
            <div class="detail-label">Ngữ cảnh kết nối (Client / OS User / Host)</div>
            <div class="detail-val mono">${escapeHtml(a.context || '—')}</div>
          </div>
        </div>
        <div>
          <div class="detail-label" style="margin-bottom:6px;">Chi tiết phát hiện / Lệnh SQL khớp vi phạm</div>
          <div class="sql-full-box">${escapeHtml(a.details || '(Không có thêm chi tiết)')}</div>
        </div>
      `;
      document.getElementById('audit-modal').classList.add('open');
    }

    function openAuditModal(idx) {
      const row = (window._filteredAudit || cachedAuditLogs)[idx];
      if (!row) return;
      currentModalSql = String(row.SQL_TEXT || '');
      const code = Number(row.RETURN_CODE || 0);
      const statusText = code === 0 ? '0 — Thực thi thành công (OK)' : `ORA-${code} — Thực thi thất bại / Vi phạm`;
      const objFull = row.OBJECT_SCHEMA && row.OBJECT_NAME ? `${row.OBJECT_SCHEMA}.${row.OBJECT_NAME}` : (row.OBJECT_NAME || '—');

      document.getElementById('modal-title-text').textContent = 'Chi tiết Bản ghi Kiểm toán (Unified Audit Trail)';
      const body = document.getElementById('audit-modal-body');
      body.innerHTML = `
        <div class="detail-grid">
          <div class="detail-item">
            <div class="detail-label">Thời gian sự kiện</div>
            <div class="detail-val mono">${escapeHtml(row.EVENT_TIMESTAMP)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Tài khoản CSDL</div>
            <div class="detail-val"><strong>${escapeHtml(row.DBUSERNAME)}</strong></div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Hành động &amp; Loại Audit</div>
            <div class="detail-val">
              <span class="badge badge-neutral">${escapeHtml(row.ACTION_NAME)}</span>
              <span class="badge badge-neutral">${escapeHtml(row.AUDIT_TYPE || 'Standard')}</span>
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Mã trả về (Return Code)</div>
            <div class="detail-val">
              <span class="badge ${code === 0 ? 'badge-success' : 'badge-critical'} mono">${escapeHtml(statusText)}</span>
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Đối tượng tác động</div>
            <div class="detail-val mono">${escapeHtml(objFull)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Chính sách FGA / Unified Audit</div>
            <div class="detail-val mono">${escapeHtml(row.FGA_POLICY_NAME || row.UNIFIED_AUDIT_POLICIES || '—')}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Tài khoản HĐH &amp; Máy trạm</div>
            <div class="detail-val mono">${escapeHtml((row.OS_USERNAME || '—') + ' @ ' + (row.USERHOST || '—'))}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Phần mềm kết nối</div>
            <div class="detail-val mono">${escapeHtml(row.CLIENT_PROGRAM_NAME || '—')}</div>
          </div>
        </div>
        <div>
          <div class="detail-label" style="margin-bottom:6px;">Câu lệnh SQL (SQL_TEXT)</div>
          <div class="sql-full-box">${escapeHtml(row.SQL_TEXT || '(Không có câu lệnh SQL)')}</div>
        </div>
      `;
      document.getElementById('audit-modal').classList.add('open');
    }

    function closeAuditModal() {
      document.getElementById('audit-modal').classList.remove('open');
    }

    function copyModalSql() {
      if (!currentModalSql) {
        showToast('Không có câu lệnh SQL để sao chép', 'error');
        return;
      }
      navigator.clipboard.writeText(currentModalSql).then(() => {
        showToast('Đã sao chép câu lệnh SQL vào clipboard!');
      });
    }

    /* ACTION HANDLERS */
    async function userAction(username, action) {
      try {
        const res = await fetch('/api/user-action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, action })
        });
        const data = await res.json();
        showToast(data.message, data.ok ? 'success' : 'error');
        refreshData(false);
      } catch (e) {
        showToast('Lỗi thực thi thao tác User', 'error');
      }
    }

    async function clearAlerts(target) {
      try {
        const res = await fetch('/api/clear-alerts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target })
        });
        const data = await res.json();
        showToast(data.message, data.ok ? 'success' : 'error');
        refreshData(false);
      } catch (e) {
        showToast('Không thể xóa cảnh báo', 'error');
      }
    }

    async function clearSingleTrigger(alertId) {
      try {
        const res = await fetch('/api/clear-alerts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: 'single_trigger', alert_id: alertId })
        });
        const data = await res.json();
        showToast(data.message, data.ok ? 'success' : 'error');
        refreshData(false);
      } catch (e) {
        showToast('Không thể xóa dòng Trigger', 'error');
      }
    }

    async function dismissSingleIdsAlert(idx) {
      const list = window._currentAlerts || cachedData.alerts || [];
      const item = list[idx];
      if (!item) return;
      try {
        const res = await fetch('/api/clear-alerts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: 'single_ids', alert_key: item.key })
        });
        const data = await res.json();
        showToast(data.message, data.ok ? 'success' : 'error');
        refreshData(false);
      } catch (e) {
        showToast('Không thể xóa cảnh báo', 'error');
      }
    }

    async function toggleAutoResponse(enabled) {
      try {
        const res = await fetch('/api/toggle-ips', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ auto_response: enabled })
        });
        const data = await res.json();
        showToast(data.auto_response ? 'Đã BẬT Tự động Phản ứng IPS' : 'Đã TẮT Tự động Phản ứng IPS');
        refreshData(false);
      } catch (e) {
        showToast('Không thể cập nhật cấu hình IPS', 'error');
      }
    }

    function toggleAutoRefresh(enabled) {
      if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
      }
      if (enabled) {
        autoRefreshTimer = setInterval(() => refreshData(false), 5000);
      }
    }

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') closeAuditModal();
    });

    // Initial boot
    refreshData(true);
    toggleAutoRefresh(true);
  </script>
</body>
</html>
"""


DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')

def get_html_page():
    if os.path.exists(DASHBOARD_HTML_PATH):
        try:
            with open(DASHBOARD_HTML_PATH, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            pass
    return HTML_PAGE


class IDSRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_text):
        body = html_text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(get_html_page())
        elif parsed.path == "/api/data":
            qs = parse_qs(parsed.query)
            do_flush = qs.get("flush", ["0"])[0] == "1"
            data = get_dashboard_data(do_flush=do_flush)
            self._send_json(data)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(raw_body)
        except Exception:
            payload = {}

        if parsed.path == "/api/user-action":
            username = payload.get("username", "")
            action = payload.get("action", "")
            if action == "lock":
                ok, msg = lock_user(username)
            elif action == "unlock":
                ok, msg = unlock_user(username)
            elif action == "revoke_dml":
                ok, msg = revoke_dml_user(username)
            elif action == "grant_dml":
                ok, msg = grant_dml_user(username)
            else:
                ok, msg = False, "Hành động không hợp lệ"
            self._send_json({"ok": ok, "message": msg})
        elif parsed.path == "/api/clear-alerts":
            target = payload.get("target", "all")
            alert_id = payload.get("alert_id")
            alert_key = payload.get("alert_key")
            ok, msg = clear_alert_history(
                target=target,
                alert_id=alert_id,
                alert_key=alert_key,
                reviewed_keys=payload.get("reviewed_keys"),
                reviewed_fga_keys=payload.get("reviewed_fga_keys"),
                reviewed_trigger_ids=payload.get("reviewed_trigger_ids"),
                reviewed_audit_keys=payload.get("reviewed_audit_keys"),
            )
            self._send_json({"ok": ok, "message": msg})
        elif parsed.path == "/api/toggle-ips":
            APP_STATE["auto_response"] = bool(payload.get("auto_response", True))
            save_persisted_state()
            self._send_json({"ok": True, "auto_response": APP_STATE["auto_response"]})
        else:
            self.send_error(404, "Not Found")


def find_free_port(preferred_port=8050):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", preferred_port)) != 0:
            return preferred_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]




def sync_with_web_dashboard():
    dashboard_url = os.getenv("DASHBOARD_URL", "http://localhost:3000")
    print(f"[*] Live Telemetry Bridge dang ket noi toi Web Dashboard: {dashboard_url}")
    print("[*] Dang lang nghe su kien thoi gian thuc tu Oracle SQL Developer...")
    last_alerts = 0
    last_triggers = 0
    connected_once = False
    while True:
        try:
            data = get_dashboard_data(do_flush=True)
            if data and data.get("ok"):
                cur_alerts = len(data.get("alerts", []))
                cur_trigs = len(data.get("triggers", []))
                if cur_alerts > last_alerts and last_alerts > 0:
                    diff = cur_alerts - last_alerts
                    print(f"\n[!] CANH BAO IDS MOI TAI ORACLE: Phat hien {diff} su kien FGA / Bat thuong!")
                last_alerts = cur_alerts
                if cur_trigs > last_triggers and last_triggers > 0:
                    diff = cur_trigs - last_triggers
                    print(f"\n[!] TRIGGER NOI SINH KICH HOAT: Da chan {diff} hanh vi vi pham du lieu!")
                last_triggers = cur_trigs

                req = urllib.request.Request(
                    f"{dashboard_url}/api/oracle-sync",
                    data=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                    headers={"Content-Type": "application/json; charset=utf-8"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if not connected_once:
                        print("[+] KET NOI THANH CONG VOI WEB DASHBOARD! (Trang thai: LIVE SYNC ON)")
                        connected_once = True
                    reply = json.loads(resp.read().decode("utf-8"))
                    for cmd in reply.get("pending_commands", []):
                        c_type = cmd.get("type")
                        payload = cmd.get("payload", {})
                        if c_type == "user_action":
                            act = payload.get("action")
                            usr = payload.get("username")
                            if act == "lock":
                                lock_user(usr)
                                print(f"[-] Dashboard yeu cau: KHOA tai khoan {usr}")
                            elif act == "unlock":
                                unlock_user(usr)
                                print(f"[+] Dashboard yeu cau: MO KHOA tai khoan {usr}")
                            elif act == "revoke_dml":
                                revoke_dml_user(usr)
                                print(f"[-] Dashboard yeu cau: HA QUYEN READ-ONLY tai khoan {usr}")
                            elif act == "grant_dml":
                                grant_dml_user(usr)
                                print(f"[+] Dashboard yeu cau: CAP FULL DML tai khoan {usr}")
                        elif c_type == "clear_alerts":
                            clear_alert_history(
                                target=payload.get("target", "all"),
                                alert_id=payload.get("alert_id"),
                                alert_key=payload.get("alert_key"),
                                reviewed_keys=payload.get("reviewed_keys"),
                                reviewed_fga_keys=payload.get("reviewed_fga_keys"),
                                reviewed_trigger_ids=payload.get("reviewed_trigger_ids"),
                                reviewed_audit_keys=payload.get("reviewed_audit_keys"),
                            )
                            print("[*] Dashboard yeu cau: Da reset / xoa lich su canh bao.")
                        elif c_type == "toggle_ips":
                            APP_STATE["auto_response"] = bool(payload.get("auto_response", True))
                            save_persisted_state()
        except Exception:
            pass
        time.sleep(2)

def main():
    ensure_utf8_database_objects()
    threading.Thread(target=sync_with_web_dashboard, daemon=True).start()
    port = find_free_port(PORT)
    server = ThreadingHTTPServer(("127.0.0.1", port), IDSRequestHandler)
    url = f"http://localhost:{port}"
    print("=" * 68)
    print("  ORACLE DB-IDS | DEFENSE-IN-DEPTH & GRADUATED ACTIVE IPS")
    print(f"  Dia chi truy cap : {url}")
    print(f"  Ket noi Oracle   : {DB_DSN} (User: {DB_USER.upper()})")
    print("  Nhan Ctrl+C de dung server.")
    print("=" * 68)

    if os.getenv("NO_BROWSER") != "1":
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDang dung Oracle DB-IDS Server...")
        server.server_close()


if __name__ == "__main__":
    main()
