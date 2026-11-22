-- =================================================================================
-- KỊCH BẢN KHỞI TẠO HỆ THỐNG AN TOÀN CSDL & PHÁT HIỆN XÂM NHẬP (ORACLE 23ai DB-IDS)
-- Kiến trúc Defense-in-Depth: Trigger nội sinh + DBMS_FGA + Honeytoken + Unified Audit
-- =================================================================================

-- =================================================================================
-- HƯỚNG DẪN CẤU HÌNH MẬT KHẨU AN TOÀN (SQL*Plus / SQLcl / SQL Developer)
--   Không lưu mật khẩu yếu hoặc mật khẩu thật trong mã nguồn DDL.
--   Trước khi chạy script này lần đầu, hãy DEFINE mật khẩu mạnh cho U1..U4:
--     DEFINE u1_pass = 'CHANGE_ME_U1_STRONG_PWD'
--     DEFINE u2_pass = 'CHANGE_ME_U2_STRONG_PWD'
--     DEFINE u3_pass = 'CHANGE_ME_U3_STRONG_PWD'
--     DEFINE u4_pass = 'CHANGE_ME_U4_STRONG_PWD'
--   Hoặc chạy tương tác qua ACCEPT trên SQL*Plus / SQLcl (bỏ chú thích nếu dùng):
--     ACCEPT u1_pass CHAR PROMPT 'Nhap mat khau manh cho U1: ' HIDE
--     ACCEPT u2_pass CHAR PROMPT 'Nhap mat khau manh cho U2: ' HIDE
--     ACCEPT u3_pass CHAR PROMPT 'Nhap mat khau manh cho U3: ' HIDE
--     ACCEPT u4_pass CHAR PROMPT 'Nhap mat khau manh cho U4: ' HIDE
--   Lưu ý: Khi chạy lại trên user đã tồn tại, script chỉ mở khóa (ACCOUNT UNLOCK)
--          và giữ nguyên mật khẩu hiện có.
-- =================================================================================
DEFINE u1_pass = '&u1_pass'
DEFINE u2_pass = '&u2_pass'
DEFINE u3_pass = '&u3_pass'
DEFINE u4_pass = '&u4_pass'

-- 1. Khởi tạo an toàn các user nghiệp vụ / thực nghiệm (U1, U2, U3, U4)
--    Chỉ tạo mới khi chưa tồn tại; nếu đã có thì giữ nguyên mật khẩu, chỉ ACCOUNT UNLOCK
DECLARE
    v_exists NUMBER;
BEGIN
    FOR u IN (
        SELECT 'U1' AS usr, q'~&u1_pass~' AS pwd FROM DUAL UNION ALL
        SELECT 'U2' AS usr, q'~&u2_pass~' AS pwd FROM DUAL UNION ALL
        SELECT 'U3' AS usr, q'~&u3_pass~' AS pwd FROM DUAL UNION ALL
        SELECT 'U4' AS usr, q'~&u4_pass~' AS pwd FROM DUAL
    ) LOOP
        SELECT COUNT(*) INTO v_exists FROM dba_users WHERE username = u.usr;

        IF v_exists = 0 THEN
            IF u.pwd IS NULL
               OR NVL(LENGTH(TRIM(u.pwd)), 0) < 8
               OR UPPER(u.pwd) LIKE 'CHANGE_ME%'
               OR SUBSTR(u.pwd, 1, 1) = CHR(38)
               OR UPPER(u.pwd) = u.usr || '123'
               OR INSTR(u.pwd, '"') > 0 THEN
                RAISE_APPLICATION_ERROR(
                    -20010,
                    'Mat khau cho user ' || u.usr || ' khong hop le hoac van la placeholder. Vui long DEFINE mat khau manh (>= 8 ky tu, khong chua dau ngoac kep).'
                );
            END IF;
            EXECUTE IMMEDIATE 'CREATE USER ' || u.usr || ' IDENTIFIED BY "' || u.pwd || '"';
        ELSE
            EXECUTE IMMEDIATE 'ALTER USER ' || u.usr || ' ACCOUNT UNLOCK';
        END IF;

        EXECUTE IMMEDIATE 'GRANT CREATE SESSION, CREATE TABLE, UNLIMITED TABLESPACE TO ' || u.usr;
    END LOOP;
END;
/

-- 2. Tạo bảng Nhân Viên chứa dữ liệu nhạy cảm & View thống kê an toàn
-- Lưu ý kỹ thuật Oracle 23ai: Package DBMS_FGA không cho phép gắn policy trực tiếp lên
-- bảng thuộc sở hữu vật lý của SYS (ORA-46399). Do đó bảng vật lý được đặt tại SYSTEM.NV
-- và tạo Synonym SYS.NV (cùng Public Synonym NV) trỏ tới SYSTEM.NV để mọi câu lệnh
-- truy vấn/phân quyền trên SYS.NV hoạt động hoàn toàn trong suốt.
BEGIN
    FOR r IN (
        SELECT owner, object_type
        FROM dba_objects
        WHERE object_name = 'NV' AND owner IN ('SYS', 'SYSTEM')
    ) LOOP
        IF r.object_type = 'TABLE' THEN
            EXECUTE IMMEDIATE 'DROP TABLE ' || r.owner || '.NV CASCADE CONSTRAINTS PURGE';
        ELSIF r.object_type = 'SYNONYM' THEN
            EXECUTE IMMEDIATE 'DROP SYNONYM ' || r.owner || '.NV';
        END IF;
    END LOOP;
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE SYSTEM.NV (
    manv VARCHAR2(10) PRIMARY KEY,
    hoten VARCHAR2(50),
    luong NUMBER(10,2),
    gioitinh VARCHAR2(10),
    cmnd VARCHAR2(20)
);

CREATE OR REPLACE SYNONYM SYS.NV FOR SYSTEM.NV;
CREATE OR REPLACE PUBLIC SYNONYM NV FOR SYSTEM.NV;

INSERT INTO SYS.NV VALUES ('NV1', 'Nguyen Van A', 900, 'Nam', '001206012345');
INSERT INTO SYS.NV VALUES ('NV2', 'Tran Thi B', 850, 'Nu', '001206099999');
INSERT INTO SYS.NV VALUES ('NV3', 'Le Van C', 1200, 'Nam', '001206088888');
INSERT INTO SYS.NV VALUES ('NV4', 'Pham Thi D', 950, 'Nu', '001206534243');

-- [YÊU CẦU 1.1] Bẫy dữ liệu (Honeytoken / Canary Record)
-- Trong nghiệp vụ bình thường không ai truy vấn mã NV_TRAP; hễ chạm vào là dấu hiệu quét/dump dữ liệu
INSERT INTO SYS.NV VALUES ('NV_TRAP', 'Hoang Van Sếp (VIP)', 99999, 'Nam', '001099000000');
COMMIT;

-- Cấp quyền thao tác bảng NV cho U1, U2, U3 và U4
GRANT SELECT, INSERT, UPDATE, DELETE ON SYS.NV TO U1, U2, U3, U4;

-- View thống kê an toàn: loại trừ bản ghi bẫy NV_TRAP và cột CMND
-- Giúp các truy vấn thống kê hợp lệ không bao giờ chạm bẫy Honeytoken
CREATE OR REPLACE VIEW SYSTEM.NV_SAFE_VIEW AS
SELECT manv, hoten, luong, gioitinh
FROM SYSTEM.NV
WHERE manv <> 'NV_TRAP';

CREATE OR REPLACE SYNONYM SYS.NV_SAFE_VIEW FOR SYSTEM.NV_SAFE_VIEW;
CREATE OR REPLACE PUBLIC SYNONYM NV_SAFE_VIEW FOR SYSTEM.NV_SAFE_VIEW;

GRANT SELECT ON SYS.NV_SAFE_VIEW TO U1, U2, U3, U4;

-- 3. Tạo bảng lưu vết cảnh báo từ Trigger nội sinh / FGA Handler & bảng chuẩn lương chống Salami Attack
BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE SYS.IDS_TRIGGER_ALERTS PURGE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE SYS.IDS_TRIGGER_ALERTS (
    alert_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT SYSTIMESTAMP,
    db_user VARCHAR2(50),
    attack_type VARCHAR2(100),
    details VARCHAR2(4000)
);

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE SYS.IDS_SALARY_BASELINES PURGE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE SYS.IDS_SALARY_BASELINES (
    manv VARCHAR2(10) PRIMARY KEY,
    base_luong NUMBER(10,2) NOT NULL,
    max_allowed_luong NUMBER(10,2) NOT NULL,
    updated_at TIMESTAMP DEFAULT SYSTIMESTAMP
);

INSERT INTO SYS.IDS_SALARY_BASELINES (manv, base_luong, max_allowed_luong)
SELECT manv, luong, luong * 1.5
FROM SYSTEM.NV
WHERE manv IN ('NV1', 'NV2', 'NV3', 'NV4');
COMMIT;

-- 4. Tạo Trigger nội sinh: Chặn xóa nhân viên, chặn Salami Attack tăng lương tích lũy,
--    và bảo vệ tính toàn vẹn DML / thông tin PII (CMND, HOTEN) trên bảng SYSTEM.NV
CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV
BEFORE INSERT OR UPDATE OR DELETE ON SYSTEM.NV
FOR EACH ROW
DECLARE
    PRAGMA AUTONOMOUS_TRANSACTION; -- Cho phép ghi log ngay cả khi lệnh chính bị Rollback
    v_user        VARCHAR2(50);
    v_max_allowed NUMBER(10,2);
BEGIN
    v_user := UPPER(SYS_CONTEXT('USERENV', 'SESSION_USER'));

    IF v_user IN ('SYS', 'SYSTEM') THEN
        RETURN;
    END IF;

    IF DELETING THEN
        INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
        VALUES (v_user, 'UNAUTHORIZED_DELETE', 'Cố tình xóa nhân viên mã: ' || :OLD.manv);
        COMMIT;
        RAISE_APPLICATION_ERROR(-20001, 'IDS BLOCK: Ban khong duoc phep xoa du lieu nhan vien!');
    END IF;

    IF INSERTING THEN
        IF UPPER(TRIM(:NEW.manv)) = 'NV_TRAP'
           OR :NEW.luong IS NULL
           OR :NEW.luong <= 0
           OR :NEW.luong > 5000 THEN
            INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
            VALUES (
                v_user,
                'UNAUTHORIZED_DML_INTEGRITY',
                'Từ chối INSERT vi phạm toàn vẹn dữ liệu: manv=' || NVL(:NEW.manv, 'NULL')
                || ', luong=' || NVL(TO_CHAR(:NEW.luong), 'NULL')
            );
            COMMIT;
            RAISE_APPLICATION_ERROR(-20004, 'IDS BLOCK (ORA-20004): Tu choi INSERT vi pham tinh toan ven du lieu / luong bat thuong!');
        END IF;
    END IF;

    IF UPDATING('LUONG') THEN
        BEGIN
            SELECT max_allowed_luong
            INTO v_max_allowed
            FROM SYS.IDS_SALARY_BASELINES
            WHERE manv = :OLD.manv;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                v_max_allowed := NULL;
        END;

        IF :NEW.luong IS NULL
           OR :NEW.luong <= 0
           OR (:OLD.luong IS NOT NULL AND :NEW.luong > :OLD.luong * 1.5)
           OR (:OLD.luong IS NOT NULL AND :NEW.luong < :OLD.luong * 0.5)
           OR (v_max_allowed IS NOT NULL AND :NEW.luong > v_max_allowed)
           OR (:OLD.manv <> 'NV_TRAP' AND :NEW.luong > 5000) THEN
            INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
            VALUES (
                v_user,
                'ABNORMAL_SALARY_MODIFICATION',
                'Thay đổi lương bất thường từ ' || NVL(TO_CHAR(:OLD.luong), 'NULL')
                || ' lên ' || NVL(TO_CHAR(:NEW.luong), 'NULL')
                || ' (manv: ' || :OLD.manv
                || CASE WHEN v_max_allowed IS NOT NULL THEN ', trần tích lũy: ' || TO_CHAR(v_max_allowed) ELSE '' END
                || ')'
            );
            COMMIT;
            RAISE_APPLICATION_ERROR(-20002, 'IDS BLOCK: Phat hien hanh vi gian lan thay doi luong vuot nguong hoac Salami Attack!');
        END IF;
    END IF;

    IF UPDATING('MANV') AND (:NEW.manv IS NULL OR :NEW.manv <> :OLD.manv) THEN
        INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
        VALUES (
            v_user,
            'UNAUTHORIZED_DML_INTEGRITY',
            'Cố tình thay đổi khóa chính MANV từ ' || :OLD.manv || ' thành ' || NVL(:NEW.manv, 'NULL')
        );
        COMMIT;
        RAISE_APPLICATION_ERROR(-20004, 'IDS BLOCK (ORA-20004): Khong duoc phep thay doi ma nhan vien (MANV)!');
    END IF;

    IF UPDATING('CMND') OR UPDATING('HOTEN') THEN
        IF :NEW.cmnd IS NULL
           OR NVL(LENGTH(TRIM(:NEW.cmnd)), 0) < 9
           OR :NEW.hoten IS NULL
           OR NVL(LENGTH(TRIM(:NEW.hoten)), 0) < 2
           OR NVL(:NEW.cmnd, '~') <> NVL(:OLD.cmnd, '~')
           OR NVL(:NEW.hoten, '~') <> NVL(:OLD.hoten, '~') THEN
            INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
            VALUES (
                v_user,
                'UNAUTHORIZED_DML_INTEGRITY',
                'Cố tình xóa trắng hoặc giả mạo PII (CMND/HOTEN) của nhân viên mã: ' || :OLD.manv
            );
            COMMIT;
            RAISE_APPLICATION_ERROR(-20004, 'IDS BLOCK (ORA-20004): Khong duoc phep xoa trang hoac gia mao thong tin dinh danh (CMND/HOTEN)!');
        END IF;
    END IF;
END;
/

-- =================================================================================
-- 5. [YÊU CẦU 1.2] Kiểm toán mịn theo điều kiện dữ liệu (Fine-Grained Auditing - DBMS_FGA)
-- =================================================================================
-- Single Source of Truth cho Handler chặn tức thời (ORA-20003) khi chạm bẫy Honeytoken NV_TRAP.
-- Lưu ý kỹ thuật Oracle: REGEXP_LIKE không hỗ trợ biên từ kiểu Perl; dùng POSIX ERE (^|[^A-Z0-9_])...([^A-Z0-9_]|$).
-- Không miễn trừ COUNT/SUM/AVG: mọi truy vấn chạm NV_TRAP đều bị ghi vết và chặn tức thời.
CREATE OR REPLACE PROCEDURE SYS.IDS_FGA_TRAP_HANDLER(
    object_schema VARCHAR2,
    object_name   VARCHAR2,
    policy_name   VARCHAR2
) AS
    PRAGMA AUTONOMOUS_TRANSACTION;
    v_user VARCHAR2(100);
    v_sql  VARCHAR2(4000);
    v_type VARCHAR2(100) := 'HONEYTOKEN_TRAP_BLOCK';
BEGIN
    v_user := UPPER(SYS_CONTEXT('USERENV', 'SESSION_USER'));
    IF v_user IN ('SYS', 'SYSTEM') THEN
        RETURN;
    END IF;

    v_sql := SUBSTR(SYS_CONTEXT('USERENV', 'CURRENT_SQL'), 1, 2000);

    IF v_sql IS NOT NULL AND (
        REGEXP_LIKE(
            v_sql,
            '(^|[^A-Z0-9_])(OR([[:space:]]+\(?|\()[[:space:]]*(1[[:space:]]*=[[:space:]]*1|2[[:space:]]*=[[:space:]]*2)|OR[[:space:]]*\(?[[:space:]]*''1''[[:space:]]*=[[:space:]]*''1''|UNION([[:space:]]+ALL)?[[:space:]]+SELECT)([^A-Z0-9_]|$)',
            'i'
        )
        OR REGEXP_LIKE(v_sql, '(--|/\*)')
        OR REGEXP_LIKE(
            v_sql,
            '(^|[^A-Z0-9_])(DBMS_PIPE|DBMS_LOCK[[:space:]]*\.[[:space:]]*SLEEP|UTL_HTTP|UTL_INADDR|UTL_FILE)([^A-Z0-9_]|$)',
            'i'
        )
    ) THEN
        v_type := 'SQL_INJECTION_BLOCK';
    END IF;

    INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)
    VALUES (
        v_user,
        v_type,
        NVL(v_sql, 'Truy cap trai phep ban ghi bay NV_TRAP (' || policy_name || ')')
    );
    COMMIT;

    RAISE_APPLICATION_ERROR(
        -20003,
        'IDS ACTIVE BLOCK (ORA-20003): Phat hien hanh vi doc trom du lieu nhay cam / SQL Injection cham bay Honeytoken NV_TRAP! Truy van bi tu choi tuc thoi!'
    );
END;
/

-- Policy FGA 1: Bẫy Honeytoken (FGA_HONEYTOKEN_TRAP)
-- Kích hoạt ngay khi có lệnh SELECT, UPDATE, DELETE chạm vào bản ghi bẫy manv = 'NV_TRAP'
BEGIN
    BEGIN
        DBMS_FGA.DROP_POLICY(
            object_schema => 'SYSTEM',
            object_name   => 'NV',
            policy_name   => 'FGA_HONEYTOKEN_TRAP'
        );
    EXCEPTION WHEN OTHERS THEN NULL;
    END;

    DBMS_FGA.ADD_POLICY(
        object_schema   => 'SYSTEM',
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
/

-- Policy FGA 2: Giám sát truy cập lương & thông tin nhạy cảm trên toàn bộ nhân viên (FGA_HIGH_SALARY_ACCESS)
-- Bao phủ tất cả bản ghi (audit_condition => NULL) khi động tới một trong các cột LUONG, CMND
BEGIN
    BEGIN
        DBMS_FGA.DROP_POLICY(
            object_schema => 'SYSTEM',
            object_name   => 'NV',
            policy_name   => 'FGA_HIGH_SALARY_ACCESS'
        );
    EXCEPTION WHEN OTHERS THEN NULL;
    END;

    DBMS_FGA.ADD_POLICY(
        object_schema     => 'SYSTEM',
        object_name       => 'NV',
        policy_name       => 'FGA_HIGH_SALARY_ACCESS',
        audit_condition   => NULL,
        audit_column      => 'LUONG, CMND',
        statement_types   => 'SELECT, UPDATE, DELETE',
        enable            => TRUE,
        audit_column_opts => DBMS_FGA.ANY_COLUMNS
    );
END;
/

-- =================================================================================
-- 6. Cấu hình Unified Auditing Policies (Tích hợp IDS Sensor)
-- =================================================================================
DECLARE
    PROCEDURE drop_policy_if_exists(p_policy_name IN VARCHAR2) IS
    BEGIN
        FOR e IN (
            SELECT DISTINCT entity_name
            FROM audit_unified_enabled_policies
            WHERE policy_name = UPPER(p_policy_name)
        ) LOOP
            BEGIN
                IF e.entity_name = 'ALL USERS' THEN
                    EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p_policy_name;
                ELSE
                    EXECUTE IMMEDIATE 'NOAUDIT POLICY ' || p_policy_name || ' BY ' || DBMS_ASSERT.ENQUOTE_NAME(e.entity_name, FALSE);
                END IF;
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
        END LOOP;

        BEGIN
            EXECUTE IMMEDIATE 'DROP AUDIT POLICY ' || p_policy_name;
        EXCEPTION WHEN OTHERS THEN NULL;
        END;
    END drop_policy_if_exists;
BEGIN
    -- Xóa bỏ các policy dư thừa đã được hợp nhất vào ids_priv_abuse_pol
    drop_policy_if_exists('ids_user_mgmt_pol');
    drop_policy_if_exists('ids_privilege_pol');

    -- Policy 1: Giám sát Đăng nhập / Đăng xuất (Bắt Brute-force)
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_logon_pol ACTIONS LOGON, LOGOFF';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_logon_pol';

    -- Policy 2: Giám sát câu lệnh DDL nguy hiểm
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_ddl_pol ACTIONS CREATE TABLE, DROP TABLE, ALTER TABLE, TRUNCATE TABLE';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_ddl_pol';

    -- Policy 3: Giám sát mọi thao tác DML (kể cả SELECT để bắt SQL Injection & Statistical Inference) trên bảng SYSTEM.NV
    drop_policy_if_exists('ids_dml_nv_pol');
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_dml_nv_pol ACTIONS SELECT, INSERT, UPDATE, DELETE ON SYSTEM.NV';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_dml_nv_pol';

    -- [YÊU CẦU 1.3] Policy 4: Mở rộng Unified Audit Policies (Chống leo thang đặc quyền & Backdoor)
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_priv_abuse_pol ACTIONS GRANT, REVOKE, CREATE USER, ALTER USER, DROP USER, ALTER SYSTEM, SET ROLE';
    EXCEPTION
        WHEN OTHERS THEN
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS GRANT';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS REVOKE';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS CREATE USER';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS ALTER USER';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS DROP USER';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS ALTER SYSTEM';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_priv_abuse_pol ADD ACTIONS SET ROLE';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_priv_abuse_pol';

    -- Policy 5: Giám sát hành vi thay đổi cấu hình bảo mật & kiểm toán
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_security_violations_pol ACTIONS ALTER DATABASE, AUDIT, NOAUDIT';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_security_violations_pol';

    -- Policy 6: Giám sát truy cập khóa mã hóa TDE & gói mật mã (ids_crypto_key_pol)
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_crypto_key_pol ACTIONS ADMINISTER KEY MANAGEMENT, SELECT ON SYS.V_$ENCRYPTION_KEYS, SELECT ON SYS.V_$ENCRYPTION_WALLET, SELECT ON SYS.ENC$, EXECUTE ON SYS.DBMS_CRYPTO';
    EXCEPTION
        WHEN OTHERS THEN
            BEGIN
                EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_crypto_key_pol ACTIONS ADMINISTER KEY MANAGEMENT';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS ADMINISTER KEY MANAGEMENT';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS SELECT ON SYS.V_$ENCRYPTION_KEYS';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS SELECT ON SYS.V_$ENCRYPTION_WALLET';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS SELECT ON SYS.ENC$';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
            BEGIN
                EXECUTE IMMEDIATE 'ALTER AUDIT POLICY ids_crypto_key_pol ADD ACTIONS EXECUTE ON SYS.DBMS_CRYPTO';
            EXCEPTION WHEN OTHERS THEN NULL;
            END;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_crypto_key_pol';
END;
/
