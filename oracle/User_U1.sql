-- =================================================================================
-- CHÚ Ý QUAN TRỌNG TRONG ORACLE SQL DEVELOPER:
-- Nhìn lên góc TRÊN BÊN PHẢI của tab User_U1.sql này có ô chọn kết nối (Connection).
-- Hãy chuyển từ [SYS_FREEPDB1] sang [User_U1] để thực hiện tấn công đúng vai User U1!
-- =================================================================================

-- Lệnh 1: Cố tình gian lận tăng lương của NV1 từ 900 lên 10000 (vượt ngưỡng > 50%)
UPDATE SYS.NV SET luong = 10000 WHERE manv = 'NV1';

-- Lệnh 2: Cố tình xóa nhân viên NV2 khỏi công ty
DELETE FROM SYS.NV WHERE manv = 'NV2';

SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;

select * from sys.nv where manv ='NV1';

SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';
SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';
SELECT COUNT(*) FROM SYS.NV WHERE gioitinh = 'Nam';

SELECT COUNT(*) FROM SYS.NV WHERE luong > 900;
SELECT SUM(luong) FROM SYS.NV WHERE luong > 900;
SELECT AVG(luong) FROM SYS.NV WHERE gioitinh = 'Nu';
