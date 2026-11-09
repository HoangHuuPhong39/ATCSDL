-- =================================================================================
-- BỘ KỊCH BẢN DEMO TOÀN DIỆN: CÁC DẠNG TẤN CÔNG KỸ THUẬT & TẤN CÔNG SUY DIỄN SDB
-- Hệ thống: An toàn CSDL & Phát hiện / Ngăn chặn Xâm nhập Oracle 23ai (DB-IDS/IPS)
-- =================================================================================
-- Lưu ý trước khi chạy:
-- 1. Mở Web Dashboard: http://localhost:3000 (hoặc http://localhost:8050)
-- 2. Đảm bảo user U1 ở trạng thái OPEN và quyền FULL DML (nếu bị khóa/hạ quyền, bấm
--    "Mở khóa User" và "Khôi phục quyền DML" trên Web Dashboard).
-- 3. Mở Oracle SQL Developer, đăng nhập bằng User U1 (hoặc User được chỉ định).
-- =================================================================================


-- #################################################################################
-- PHẦN 1: CÁC DẠNG TẤN CÔNG KỸ THUẬT VÀO DBMS & ỨNG DỤNG
-- #################################################################################

-- ---------------------------------------------------------------------------------
-- 1.1. SQL INJECTION (Chèn mã độc hại làm thay đổi cấu trúc câu lệnh SQL)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mô tả: Chèn payload bypass logic hoặc trích xuất dữ liệu trái phép.
-- ---------------------------------------------------------------------------------

-- [Lệnh 1.1.A - Tautology Bypass (Luôn đúng)]:
-- Kẻ tấn công inject mệnh đề OR 1=1 để dump toàn bộ danh sách nhân viên
SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;

-- [Lệnh 1.1.B - String Tautology Bypass]:
-- Biến thể bypass chuỗi ký tự phổ biến
SELECT * FROM SYS.NV WHERE hoten = 'admin' OR '1'='1';

-- [Lệnh 1.1.C - UNION-based SQL Injection]:
-- Ghép nối câu lệnh SELECT trái phép để dò quét cấu trúc bảng hệ thống
SELECT manv, hoten, luong, gioitinh, cmnd FROM SYS.NV WHERE manv = 'NV1' 
UNION SELECT '0', banner, 0, 'SYS', '000000000000' FROM v$version;

-- [Lệnh 1.1.D - Inline Comment & Piggybacked Payload]:
SELECT * FROM SYS.NV WHERE manv = 'NV1'-- and luong < 1000;

-- => Kết quả trên Web Dashboard: Cảnh báo đỏ SQL Injection Signature (Risk Score 95 - Level 3),
--    Hệ thống IPS tự động kích hoạt cô lập tài khoản!


-- ---------------------------------------------------------------------------------
-- 1.2. GIẢ MẠO / GIẢ DANH (Masquerading Attack: Đánh cắp danh tính / Đổi mật khẩu)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mô tả: Kẻ tấn công chiếm đoạt phiên hoặc cố tình đổi mật khẩu của tài khoản hợp
--        pháp khác (U2, U3) để mạo danh đăng nhập và che giấu hành vi.
-- ---------------------------------------------------------------------------------

-- [Lệnh 1.2.A - Chiếm đoạt và đổi mật khẩu tài khoản khác]:
-- User U1 cố tình đổi mật khẩu của U2 thành mật khẩu do mình kiểm soát
ALTER USER U2 IDENTIFIED BY 'Hacked_123456';

-- [Lệnh 1.2.B - Thăm dò thông tin phiên làm việc và danh tính phiên hiện tại]:
SELECT SYS_CONTEXT('USERENV', 'SESSION_USER') AS cur_user,
       SYS_CONTEXT('USERENV', 'IP_ADDRESS')   AS cur_ip,
       SYS_CONTEXT('USERENV', 'HOST')         AS cur_host
FROM DUAL;

-- => Kết quả trên Web Dashboard: Ghi nhận cảnh báo Privilege Abuse / Masquerading Attack
--    do can thiệp vào tài khoản khác mà không có thẩm quyền DBA.


-- ---------------------------------------------------------------------------------
-- 1.3. LEO THANG ĐẶC QUYỀN (Privilege Escalation: Nâng quyền vượt mức được cấp)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mô tả: User thông thường cố gắng tự gán quyền DBA / cấp quyền hệ thống hoặc tạo
--        tài khoản cửa hậu (Backdoor User) để duy trì quyền kiểm soát.
-- ---------------------------------------------------------------------------------

-- [Lệnh 1.3.A - Tự gán quyền quản trị tối cao DBA cho bản thân]:
GRANT DBA TO U1;

-- [Lệnh 1.3.B - Cấp quyền hệ thống nhạy cảm ALTER USER / ALTER SYSTEM]:
GRANT ALTER USER, CREATE USER TO U1;

-- [Lệnh 1.3.C - Tạo tài khoản cửa hậu (Backdoor Account)]:
CREATE USER backdoor_root IDENTIFIED BY 'Hacker@2026';

-- [Lệnh 1.3.D - Cố tình gỡ bỏ giám sát kiểm toán hệ thống (Audit Evasion)]:
NOAUDIT ALL;

-- => Kết quả: Oracle từ chối ORA-01031 (Insufficient privileges).
--    Đồng thời Unified Audit bắt chính sách 'ids_priv_abuse_pol', Web Dashboard
--    phát hiện hành vi Leo thang đặc quyền (Risk Score 85 - Level 3 Isolation)!


-- ---------------------------------------------------------------------------------
-- 1.4. TẤN CÔNG ĐĂNG NHẬP THẤT BẠI (Failed Logins / Brute-Force Password Attack)
-- Thực hiện: Mở Command Prompt (cmd) và chạy lệnh thử sai mật khẩu liên tiếp
-- Mô tả: Kẻ tấn công dùng từ điển / brute-force dò mật khẩu tài khoản U1.
-- ---------------------------------------------------------------------------------

-- Chạy lần lượt 3 câu lệnh sau trong Command Prompt (hoặc terminal):
-- Lần 1 (Sai mật khẩu -> Lỗi ORA-01017):
-- sqlplus U1/SaiMatKhau1@localhost:1521/FREEPDB1

-- Lần 2 (Sai mật khẩu -> Lỗi ORA-01017):
-- sqlplus U1/SaiMatKhau2@localhost:1521/FREEPDB1

-- Lần 3 (Sai mật khẩu -> Lỗi ORA-01017):
-- sqlplus U1/SaiMatKhau3@localhost:1521/FREEPDB1

-- (Hoặc từ SQL Developer: Cố tình tạo kết nối User U1 với mật khẩu sai 3 lần liên tiếp)
-- => Kết quả trên Web Dashboard: Cảnh báo "Brute-Force Logon Attack (ORA-01017 >= 3 lần)",
--    Risk Score nhảy lên 90 (Level 3: Full Isolation), tài khoản U1 tự động bị KHÓA!


-- ---------------------------------------------------------------------------------
-- 1.5. TRUY CẬP KHÓA MÃ HÓA TRÁI PHÉP (Unauthorized Cryptographic Key Access)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mô tả: Gồm 2 hình thức:
--   - Truy cập trực tiếp: Đọc bảng hệ thống chứa khóa / Keystore TDE.
--   - Truy cập gián tiếp: Gọi các package mã hóa (DBMS_CRYPTO) để giải mã trái phép.
-- ---------------------------------------------------------------------------------

-- [Lệnh 1.5.A - Truy cập TRỰC TIẾP vào bảng/kho khóa mã hóa Oracle TDE]:
SELECT * FROM V$ENCRYPTION_KEYS;

-- [Lệnh 1.5.B - Truy cập TRỰC TIẾP vào trạng thái Keystore / Wallet]:
SELECT * FROM V$ENCRYPTION_WALLET;

-- [Lệnh 1.5.C - Dò quét các cột đang được mã hóa trong toàn CSDL]:
SELECT * FROM DBA_ENCRYPTED_COLUMNS;

-- [Lệnh 1.5.D - Truy cập GIÁN TIẾP qua dịch vụ/hàm mật mã DBMS_CRYPTO]:
DECLARE
    v_raw RAW(2000);
BEGIN
    v_raw := DBMS_CRYPTO.HASH(UTL_I18N.STRING_TO_RAW('SecretData', 'AL32UTF8'), 2);
END;
/

-- => Kết quả trên Web Dashboard: Cảnh báo "Truy cập trực tiếp kho khóa TDE / Gián tiếp qua DBMS_CRYPTO",
--    Risk Score tăng lên 80 (Level 3 - Critical Security Breach)!



-- #################################################################################
-- PHẦN 2: CÁC KIỂU TẤN CÔNG SUY DIỄN (INFERENCE ATTACKS) VÀO CSDL THỐNG KÊ (SDB)
-- Dữ liệu mẫu bảng SYS.NV:
--   NV1: Nguyen Van A  (900,  Nam, 001206012345)
--   NV2: Tran Thi B    (850,  Nu,  001206099999)
--   NV3: Le Van C      (1200, Nam, 001206088888)
--   NV4: Pham Thi D    (950,  Nu,  001206534243)
-- #################################################################################

-- ---------------------------------------------------------------------------------
-- 2.1. TẤN CÔNG TRỰC TIẾP (Direct Attack: Truy xuất trực tiếp dữ liệu cá nhân nhạy cảm)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mục tiêu: Dùng câu lệnh SELECT thông thường để đọc cột lương & CMND của cá nhân mục tiêu.
-- ---------------------------------------------------------------------------------

-- [Lệnh 2.1.A - Đọc dữ liệu cá nhân nhạy cảm của nhân viên NV3 (Lương 1200 >= 1000)]:
SELECT manv, hoten, luong, cmnd FROM SYS.NV WHERE manv = 'NV3';

-- [Lệnh 2.1.B - Truy vấn trúng bản ghi bẫy Honeytoken (NV_TRAP)]:
SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP';

-- => Kết quả:
--    - Lệnh 2.1.A kích hoạt chính sách FGA_HIGH_SALARY_ACCESS (Cảnh báo Level 1: Monitor).
--    - Lệnh 2.1.B kích hoạt bẫy FGA_HONEYTOKEN_TRAP -> Risk Score vọt lên 95/100,
--      tự động KHÓA TÀI KHOẢN U1 tức thời!


-- ---------------------------------------------------------------------------------
-- 2.2. TẤN CÔNG DỰA VÀO ĐẾM (Count-based Attack: Kết hợp COUNT = 1 và SUM)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mục tiêu: Trong CSDL thống kê cấm đọc chi tiết dòng, kẻ tấn công kết hợp điều kiện
--          đếm COUNT = 1 và hàm SUM để bóc trần chính xác lương của cá nhân mục tiêu!
-- ---------------------------------------------------------------------------------

-- Bước 1: Thử điều kiện lọc xem tập kết quả có duy nhất 1 cá nhân hay không:
SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nu' AND luong < 900;
-- => Kết quả: COUNT = 1 (Xác nhận chỉ có duy nhất 1 người thỏa mãn: Tran Thi B)

-- Bước 2: Dùng hàm SUM trên cùng điều kiện lọc đó:
SELECT SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nu' AND luong < 900;
-- => Kết quả: SUM = 850.
-- => Suy diễn: Vì tập chỉ có 1 người, nên lương của Tran Thi B chắc chắn bằng 850!

-- => Kết quả trên Web Dashboard: Cảnh báo "SDB Count-based Attack (COUNT=1 & SUM)",
--    Risk Score = 65 (Level 2: Hạ quyền xuống Read-Only)!


-- ---------------------------------------------------------------------------------
-- 2.3. TẤN CÔNG TRÌNH THEO DÕI (Tracker Attack: Lách kiểm soát kích cỡ tập truy vấn)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Cơ chế bảo vệ lý thuyết: Hệ thống chỉ cho phép truy vấn khi kích cỡ tập kết quả C
-- thỏa mãn: k <= |C| <= n - k (ngăn truy vấn tập quá nhỏ hoặc quá lớn).
-- Mục tiêu: Kẻ tấn công dùng biểu thức logic Tracker (OR / != / NOT) để vượt qua bộ lọc.
-- ---------------------------------------------------------------------------------

-- Mục tiêu: Tìm lương của nhân viên 'Nguyen Van A' (NV1)
-- Sử dụng biểu thức Tracker T để phân rã tập hợp:

-- [Lệnh 2.3.1]: Truy vấn tập hợp tổng quan
SELECT COUNT(*), SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam';

-- [Lệnh 2.3.2]: Truy vấn tập Tracker có điều kiện bổ sung
SELECT SUM(luong), MAX(luong) FROM SYS.NV WHERE gioitinh = 'Nam' AND luong < 5000;

-- [Lệnh 2.3.3]: Truy vấn loại trừ nhân viên mục tiêu bằng toán tử bù (!=)
SELECT COUNT(*), SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam' AND manv != 'NV1' AND luong < 5000;

-- [Lệnh 2.3.4]: Truy vấn kết hợp toán tử OR để lách ngưỡng kiểm soát kích thước
SELECT AVG(luong), MIN(luong) FROM SYS.NV WHERE luong >= 1000 OR manv = 'NV1';

-- => Công thức bóc tách của Hacker:
--    Lương(NV1) = SUM(Nam, luong < 5000) - SUM(Nam, manv != NV1, luong < 5000)
--               = 2100 - 1200 = 900!
-- => Kết quả trên Web Dashboard: Cảnh báo "SDB Tracker Attack (Lách Query-Set-Size)",
--    Risk Score = 72 (Level 2: Tự động thu hồi quyền DML -> Ép về READ-ONLY)!


-- ---------------------------------------------------------------------------------
-- 2.4. TẤN CÔNG HỆ TUYẾN TÍNH (Linear System Attack: Giải hệ phương trình A*X = B)
-- Kết nối thực hiện: User U1 (Mật khẩu: U1123)
-- Mô tả: Kẻ tấn công thực thi các truy vấn tổng hợp trên nhiều tập hợp con chồng lấn
--        để xây dựng hệ phương trình tuyến tính, sau đó dùng phép khử Gauss để tìm
--        ra toàn bộ lương của từng nhân viên mà không cần truy vấn bất kỳ dòng nào trực tiếp!
-- ---------------------------------------------------------------------------------

-- Kẻ tấn công đặt ẩn số: x1 = Lương(NV1), x2 = Lương(NV2), x3 = Lương(NV3)
-- Chạy liên tiếp 3 truy vấn thống kê độc lập tuyến tính:

-- [Phương trình 1: x1 + x2]
SELECT SUM(luong) AS eq1_x1_plus_x2 
FROM SYS.NV 
WHERE manv IN ('NV1', 'NV2');
-- => Kết quả: 1750 (Phương trình: x1 + x2 = 1750)

-- [Phương trình 2: x2 + x3]
SELECT SUM(luong) AS eq2_x2_plus_x3 
FROM SYS.NV 
WHERE manv IN ('NV2', 'NV3');
-- => Kết quả: 2050 (Phương trình: x2 + x3 = 2050)

-- [Phương trình 3: x1 + x3]
SELECT SUM(luong) AS eq3_x1_plus_x3 
FROM SYS.NV 
WHERE manv IN ('NV1', 'NV3');
-- => Kết quả: 2100 (Phương trình: x1 + x3 = 2100)

-- [Phương trình 4: Kiểm chứng thêm tổng cả 3 nhân viên]
SELECT AVG(luong), SUM(luong) AS eq4_total 
FROM SYS.NV 
WHERE manv IN ('NV1', 'NV2', 'NV3');
-- => Kết quả SUM: 2950

-- => GIẢI HỆ PHƯƠNG TRÌNH TUYẾN TÍNH (Khử Gauss):
--    (x1 + x2) + (x2 + x3) + (x1 + x3) = 1750 + 2050 + 2100 = 5900
--    => 2*(x1 + x2 + x3) = 5900  =>  x1 + x2 + x3 = 2950
--    => x3 = 2950 - (x1 + x2) = 2950 - 1750 = 1200 (Lương Le Van C)
--    => x1 = 2950 - (x2 + x3) = 2950 - 2050 = 900  (Lương Nguyen Van A)
--    => x2 = 2950 - (x1 + x3) = 2950 - 2100 = 850  (Lương Tran Thi B)
-- => Toàn bộ dữ liệu lương bảo mật đã bị lộ hoàn toàn qua suy diễn toán học!

-- => Kết quả trên Web Dashboard: Cảnh báo "SDB Linear System Attack (Giải hệ A*X = B)",
--    Risk Score = 78 (Level 2/3), Hệ thống tự động thu hồi quyền DML và đưa ra khuyến nghị
--    áp dụng Differential Privacy / Data Perturbation!
