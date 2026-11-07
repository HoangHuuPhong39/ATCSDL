-- =================================================================================
-- KỊCH BẢN KHỞI TẠO HỆ THỐNG AN TOÀN CSDL & PHÁT HIỆN XÂM NHẬP (ORACLE 23ai DB-IDS)
-- Kiến trúc Defense-in-Depth: Trigger nội sinh + DBMS_FGA + Honeytoken + Unified Audit
-- =================================================================================

-- 1. Tạo / Đặt lại các user đóng vai nhân viên / kẻ tấn công (U1, U2, U3, U4)
--    Sử dụng khối PL/SQL an toàn để chạy lại nhiều lần không bao giờ bị lỗi ORA-01920 / ORA-01917
BEGIN
    FOR u IN (
        SELECT 'U1' AS usr, 'U1123' AS pwd FROM DUAL UNION ALL
        SELECT 'U2' AS usr, 'U2123' AS pwd FROM DUAL UNION ALL
        SELECT 'U3' AS usr, 'U3123' AS pwd FROM DUAL UNION ALL
        SELECT 'U4' AS usr, 'U4123' AS pwd FROM DUAL
    ) LOOP
        BEGIN
            EXECUTE IMMEDIATE 'CREATE USER ' || u.usr || ' IDENTIFIED BY ' || u.pwd;
        EXCEPTION
            WHEN OTHERS THEN
                EXECUTE IMMEDIATE 'ALTER USER ' || u.usr || ' IDENTIFIED BY ' || u.pwd || ' ACCOUNT UNLOCK';
        END;
        EXECUTE IMMEDIATE 'GRANT CREATE SESSION, CREATE TABLE, UNLIMITED TABLESPACE TO ' || u.usr;
    END LOOP;
END;
/

-- 2. Tạo bảng Nhân Viên chứa dữ liệu nhạy cảm
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

-- 3. Tạo bảng lưu vết cảnh báo từ Trigger nội sinh (Autonomous Logging)
BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE SYS.IDS_TRIGGER_ALERTS PURGE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE SYS.IDS_TRIGGER_ALERTS (
    alert_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time TIMESTAMP DEFAULT SYSTIMESTAMP,
    db_user VARCHAR2(50),
    attack_type VARCHAR2(100),
    details VARCHAR2(4000)
);

-- 4. Tạo Trigger nội sinh: Chặn hành vi tự ý tăng lương > 50% hoặc xóa nhân viên
--    Chặn trên mọi phiên kết nối (kể cả khi chạy nhầm trên kết nối SYS_FREEPDB1)
CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV
BEFORE UPDATE OR DELETE ON SYSTEM.NV
FOR EACH ROW
DECLARE
    PRAGMA AUTONOMOUS_TRANSACTION; -- Cho phép ghi log ngay cả khi lệnh chính bị Rollback
    v_user VARCHAR2(50);
BEGIN
    v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');

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
/

-- =================================================================================
-- 5. [YÊU CẦU 1.2] Kiểm toán mịn theo điều kiện dữ liệu (Fine-Grained Auditing - DBMS_FGA)
-- =================================================================================
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
        statement_types => 'SELECT, UPDATE, DELETE',
        enable          => TRUE
    );
END;
/

-- Policy FGA 2: Giám sát truy cập lương cao & thông tin nhạy cảm (FGA_HIGH_SALARY_ACCESS)
-- Kích hoạt khi truy vấn vào các cột nhạy cảm (luong, cmnd) với điều kiện luong >= 1000
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
        object_schema   => 'SYSTEM',
        object_name     => 'NV',
        policy_name     => 'FGA_HIGH_SALARY_ACCESS',
        audit_condition => 'luong >= 1000',
        audit_column    => 'LUONG, CMND',
        statement_types => 'SELECT, UPDATE, DELETE',
        enable          => TRUE
    );
END;
/

-- =================================================================================
-- 6. Cấu hình Unified Auditing Policies (Tích hợp IDS Sensor)
-- =================================================================================
BEGIN
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

    -- Policy 3: Giám sát mọi thao tác DML (kể cả SELECT để bắt SQL Injection & Statistical Inference) trên bảng NV
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_dml_nv_pol ACTIONS SELECT, INSERT, UPDATE, DELETE ON SYSTEM.NV';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_dml_nv_pol';

    -- [YÊU CẦU 1.3] Policy 4: Mở rộng Unified Audit Policies (Chống leo thang đặc quyền & Backdoor)
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_priv_abuse_pol ACTIONS GRANT, REVOKE, CREATE USER, ALTER USER, DROP USER';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_priv_abuse_pol';

    -- Các Policy bổ trợ giám sát quản trị hệ thống
    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_user_mgmt_pol ACTIONS CREATE USER, ALTER USER, DROP USER';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_user_mgmt_pol';

    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_security_violations_pol ACTIONS ALTER DATABASE, AUDIT, NOAUDIT';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_security_violations_pol';

    BEGIN
        EXECUTE IMMEDIATE 'CREATE AUDIT POLICY ids_privilege_pol ACTIONS GRANT, REVOKE, ALTER SYSTEM, SET ROLE';
    EXCEPTION WHEN OTHERS THEN NULL;
    END;
    EXECUTE IMMEDIATE 'AUDIT POLICY ids_privilege_pol';
END;
/
