-- =================================================================================
-- KỊCH BẢN DEMO TỔNG HỢP: HỆ THỐNG AN TOÀN CSDL & PHÁT HIỆN XÂM NHẬP (ORACLE 23ai DB-IDS)
-- Hướng dẫn: Mở Oracle SQL Developer (kết nối bằng U1 hoặc U2) và Web Dashboard
-- tại địa chỉ http://localhost:8050 để quan sát trực quan từng cấp độ phản ứng.
-- =================================================================================

-- [CHUẨN BỊ TRƯỚC MỖI KỊCH BẢN TRÊN WEB DASHBOARD]
-- 1. Trên giao diện http://localhost:8050, bấm nút "Xóa lịch sử & Reset Risk Score".
-- 2. Đảm bảo U1 / U2 đang ở trạng thái "OPEN" và quyền "FULL DML" (nếu đang khóa hoặc
--    Read-Only, bấm nút "Mở khóa User" và "Khôi phục quyền DML (Grant Full)").


-- =================================================================================
-- TEST 1: TRIGGER NỘI SINH CHẶN GIAN LẬN TỨC THỜI (SYS.TRG_PROTECT_NV)
-- Mục tiêu: Chứng minh cơ chế phòng vệ tầng dữ liệu chặn đứng hành vi xóa nhân viên
-- hoặc tự ý nâng lương > 50%, đồng thời ghi vết bằng PRAGMA AUTONOMOUS_TRANSACTION
-- ngay cả khi câu lệnh giao dịch chính bị Rollback.
-- Kết nối thực hiện: U1 (Mật khẩu: U1123)
-- =================================================================================

-- 1.1. Thử cập nhật lương hợp lệ (tăng <= 50%: từ 900 lên 1000) -> THÀNH CÔNG
UPDATE SYS.NV SET luong = 1000 WHERE manv = 'NV1';
ROLLBACK;

-- 1.2. Gian lận tăng lương vượt ngưỡng > 50% (từ 900 lên 5000)
-- -> BỊ TRIGGER CHẶN TỨC THỜI (ORA-20002) & Ghi vào bảng SYS.IDS_TRIGGER_ALERTS
UPDATE SYS.NV SET luong = 5000 WHERE manv = 'NV1';

-- 1.3. Cố tình xóa trái phép dữ liệu nhân viên
-- -> BỊ TRIGGER CHẶN TỨC THỜI (ORA-20001) & Ghi vào bảng SYS.IDS_TRIGGER_ALERTS
DELETE FROM SYS.NV WHERE manv = 'NV2';

-- -> Sau khi chạy 1.2 & 1.3: Bấm "Làm mới dữ liệu (Flush Audit)" trên Dashboard.
--    Quan sát bảng "Hành vi bị chặn tức thời bởi Database Trigger" và Risk Score tăng lên Level 2 (Read-Only)!


-- =================================================================================
-- TEST 2: KIỂM TOÁN MỊN (DBMS_FGA) & CHẠM BẪY DỮ LIỆU HONEYTOKEN (NV_TRAP)
-- Mục tiêu:
--   - Bước 2A: Kiểm chứng FGA_HIGH_SALARY_ACCESS (Cảnh báo Level 1: Risk Score = 30)
--   - Bước 2B: Kiểm chứng bẫy Honeytoken FGA_HONEYTOKEN_TRAP (Phản ứng Level 3:
--     Risk Score = 95 -> Tự động KHÓA TÀI KHOẢN & NGẮT KẾT NỐI tức thời)
-- Kết nối thực hiện: U1 (Mật khẩu: U1123)
-- =================================================================================

-- [Bước 2A - Level 1 Warning] Truy vấn thông thường vào nhân viên lương thấp (< 1000)
-- -> Không kích hoạt FGA_HIGH_SALARY_ACCESS
SELECT manv, hoten, gioitinh FROM SYS.NV WHERE manv = 'NV1';

-- [Bước 2A - Level 1 Warning] Truy vấn vào cột nhạy cảm (LUONG, CMND) của nhân viên lương >= 1000
-- -> Kích hoạt FGA_HIGH_SALARY_ACCESS -> Dashboard báo Risk Score = 30 (Level 1: Monitor)
SELECT manv, hoten, luong, cmnd FROM SYS.NV WHERE manv = 'NV3';

-- [Bước 2B - Level 3 Full Isolation] Kẻ tấn công dò quét/dump trúng bản ghi bẫy Honeytoken (NV_TRAP)
-- -> Kích hoạt FGA_HONEYTOKEN_TRAP -> Risk Score vọt lên 95/100 (Level 3: CRITICAL)
-- -> IPS tự động thực thi ALTER USER U1 ACCOUNT LOCK và KILL SESSION!
SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP';

-- -> Bấm "Làm mới dữ liệu (Flush Audit)" trên Dashboard để xem sự kiện trong mục
--    "Bẫy FGA & Honeytoken" và thông báo tự động khóa tài khoản U1!


-- =================================================================================
-- TEST 3: TẤN CÔNG SUY DIỄN THỐNG KÊ (STATISTICAL INFERENCE / TRACKER ATTACK)
--         & PHẢN ỨNG HẠ QUYỀN TẠM THỜI (LEVEL 2: PRIVILEGE CONTAINMENT -> READ-ONLY)
-- Mục tiêu: Kẻ tấn công không truy vấn trực tiếp từng dòng mà dùng >= 3 câu lệnh hàm
-- thống kê (COUNT, SUM, AVG, MAX, MIN) với mệnh đề WHERE biến thiên để suy diễn lương
-- của nhân viên "Le Van C" (NV3).
-- Hệ thống sẽ chấm Risk Score = 65 (Level 2 - HIGH) và tự động thu hồi quyền DML
-- (REVOKE INSERT, UPDATE, DELETE ON SYS.NV FROM U1), đẩy U1 về chế độ READ-ONLY!
-- Kết nối thực hiện: U1 (Trước khi chạy, nhớ bấm "Mở khóa User" & "Khôi phục quyền DML" trên Dashboard)
-- =================================================================================

-- 3.1. Chạy liên tiếp 4 truy vấn thống kê có điều kiện lọc biến thiên (Tracker Queries):
SELECT COUNT(*), AVG(luong) FROM SYS.NV WHERE gioitinh = 'Nam';

SELECT SUM(luong), MAX(luong) FROM SYS.NV WHERE gioitinh = 'Nam' AND luong < 5000;

SELECT COUNT(*), SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam' AND manv != 'NV1' AND luong < 5000;

SELECT AVG(luong), MIN(luong) FROM SYS.NV WHERE luong >= 1000 AND luong < 5000;

-- 3.2. Bấm "Làm mới dữ liệu (Flush Audit)" trên Web Dashboard:
--      -> Cảnh báo "Statistical Inference Attack (Tấn công suy diễn thống kê)" xuất hiện!
--      -> Risk Score của U1 = 65/100 -> Kích hoạt Level 2 (Privilege Containment):
--         Chế độ quyền của U1 tự động chuyển từ "FULL DML" sang "READ-ONLY (Chỉ SELECT)"!

-- 3.3. Kiểm chứng chế độ Read-Only ngay trên phiên của U1:
-- Lệnh SELECT vẫn hoạt động bình thường (không gây gián đoạn đọc dữ liệu):
SELECT manv, hoten, gioitinh FROM SYS.NV WHERE manv = 'NV1';

-- Nhưng mọi lệnh sửa/thêm/xóa (UPDATE/INSERT/DELETE) ngay lập tức bị từ chối quyền (ORA-01031):
UPDATE SYS.NV SET hoten = 'Nguyen Van A (Edited)' WHERE manv = 'NV1';


-- =================================================================================
-- TEST 4: TẤN CÔNG SQL INJECTION & LEO THANG ĐẶC QUYỀN (LEVEL 3: FULL ISOLATION)
-- Mục tiêu: Phát hiện payload SQL Injection kinh điển (OR 1=1, UNION SELECT, --)
-- và hành vi cố tình tạo user cửa hậu / cấp quyền trái phép (ids_priv_abuse_pol).
-- Kết nối thực hiện: U1 (Nhớ bấm "Khôi phục quyền DML" hoặc "Xóa lịch sử" trước khi test)
-- =================================================================================

-- 4.1. Thực thi câu lệnh chứa mẫu tấn công SQL Injection vượt qua xác thực:
SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1 --;

-- 4.2. Hoặc tấn công UNION SELECT nhằm trích xuất tài khoản hệ thống:
SELECT manv, hoten FROM SYS.NV WHERE manv = 'NV1' UNION SELECT username, account_status FROM all_users;

-- 4.3. Hoặc cố tình leo thang đặc quyền / tạo tài khoản Backdoor (bị bắt bởi ids_priv_abuse_pol):
CREATE USER backdoor_hacker IDENTIFIED BY Hacker123;
GRANT DBA TO U2;

-- -> Bấm "Làm mới dữ liệu (Flush Audit)" trên Dashboard:
--    Hệ thống phát hiện SQL Injection / Privilege Escalation (Risk Score >= 85, Level 3)
--    và tự động KHÓA TÀI KHOẢN U1 + NGẮT KẾT NỐI tức thời!


-- =================================================================================
-- TEST 5: TẤN CÔNG VÉT CẠN MẬT KHẨU (BRUTE-FORCE LOGON - ORA-01017)
-- Mục tiêu: Thử đăng nhập sai mật khẩu >= 3 lần liên tiếp vào tài khoản U2.
-- Hệ thống phát hiện chuỗi sự kiện RETURN_CODE = 1017 từ Policy IDS_LOGON_POL,
-- chấm Risk Score = 90 (Level 3 - CRITICAL) và tự động khóa tài khoản U2!
-- =================================================================================

-- Cách 1: Trong SQL Developer, bấm chuột phải vào kết nối U2 -> Properties -> Nhập sai mật khẩu
--         và bấm "Test" hoặc "Connect" liên tiếp 3 lần (báo lỗi ORA-01017).
-- Cách 2: Hoặc mở Command Prompt / Terminal và chạy 3 lệnh SQL*Plus đăng nhập sai sau:
--   sqlplus -L U2/SaiMatKhau_Lan1@localhost:1521/FREEPDB1
--   sqlplus -L U2/SaiMatKhau_Lan2@localhost:1521/FREEPDB1
--   sqlplus -L U2/SaiMatKhau_Lan3@localhost:1521/FREEPDB1

-- -> Quan sát trên Dashboard: Cảnh báo "Brute-Force Logon (ORA-01017)" xuất hiện,
--    Risk Score của U2 = 90/100 và tài khoản U2 tự động chuyển sang trạng thái LOCKED!
