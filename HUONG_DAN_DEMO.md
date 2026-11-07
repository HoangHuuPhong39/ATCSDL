# KỊCH BẢN ĐỒNG BỘ & DEMO HỆ THỐNG AN TOÀN CSDL (ORACLE 23ai + WEB DASHBOARD)

## Cấu trúc thư mục D:\sqloracle:
- `D:\sqloracle\dashboardweb`: Giao diện Dashboard giám sát an ninh CSDL thời gian thực (React + Express, cổng 3000).
- `D:\sqloracle\oracle`: Dữ liệu Oracle, các script SQL (`DEMO_COMMANDS.sql`, `SYS_FREEPDB1.sql`) và Cầu nối đồng bộ tự động `bridge.py`.
- `CHAY_HE_THONG.bat`: File khởi động 1-click tự động bật cả Web Dashboard và Cầu nối Oracle.

---

## CƠ CHẾ HOẠT ĐỘNG ĐỒNG BỘ:
1. **Oracle Database (Oracle 23ai Free)**: Chạy dịch vụ tại `localhost:1521/FREEPDB1`.
2. **Cầu nối `bridge.py`**:
   - Tự động kết nối vào Oracle 23ai với quyền quản trị SYSDBA.
   - Định kỳ mỗi 2 giây gọi lệnh xả bộ nhớ kiểm toán `DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL`.
   - Quét bảng `UNIFIED_AUDIT_TRAIL`, `SYS.IDS_TRIGGER_ALERTS`, `DBA_USERS` và `SYS.NV`.
   - Đẩy dữ liệu vi phạm sang Web Dashboard (`http://localhost:3000/api/oracle-sync`).
3. **Web Dashboard**:
   - Nhận tín hiệu, hiển thị trực quan biểu đồ nhiệt, chuông báo, bản ghi vi phạm, tăng Risk Score (0 -> 100).
   - Tự động cập nhật trạng thái User (`LOCKED`, `READ-ONLY`).
   - Khi bấm nút "Mở khóa User" trên Web, lệnh sẽ được cầu nối gửi ngược lại và mở khóa trực tiếp trên Oracle!

---

## CÁC BƯỚC THỰC HIỆN KHI DEMO CHO GIÁO VIÊN:

### Bước 1: Khởi động hệ thống
- Vào thư mục `D:\sqloracle` và click đúp vào file **`CHAY_HE_THONG.bat`**.
- Mở trình duyệt truy cập: **`http://localhost:3000`**.
- Trên thanh Header của Web Dashboard, kiểm tra nút trạng thái **"Oracle Live Sync: ON"** sáng màu xanh lá.

### Bước 2: Mở Oracle SQL Developer để Demo
Mở kết nối tới Oracle (user `U1`, password `U1123`, Service `FREEPDB1`).

#### Demo 1: Trigger nội sinh chặn gian lận dữ liệu (Autonomous Transaction)
- Chạy câu lệnh gian lận tăng lương vượt 50%:
  ```sql
  UPDATE SYS.NV SET luong = 5000 WHERE manv = 'NV1';
  ```
- **Kết quả trên Oracle**: Bị chặn đứng với lỗi `ORA-20002: Lương tăng vượt ngưỡng cho phép (> 50%)`.
- **Kết quả trên Web Dashboard**: Ngay lập tức hiện thông báo chuông cảnh báo đỏ, ghi nhận tại tab **Triggers**, Risk Score của U1 tăng lên Level 2.

#### Demo 2: Kiểm toán mịn (DBMS_FGA) & Chạm bẫy Honeytoken (NV_TRAP)
- Chạy câu lệnh truy vấn quét toàn bộ bảng nhân viên (dính bản ghi bẫy):
  ```sql
  SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP';
  ```
- **Kết quả trên Web Dashboard**:
  - Bẫy `FGA_HONEYTOKEN_TRAP` kích hoạt.
  - Risk Score vọt lên **95 / 100** (Mức nguy hiểm tối đa - Level 3 CRITICAL).
  - Hệ thống tự động kích hoạt IPS: Trạng thái tài khoản U1 lập tức chuyển sang **LOCKED** (Bị cô lập hoàn toàn).

#### Demo 3: Kiểm chứng tài khoản bị khóa thực tế trên Oracle
- Quay lại Oracle SQL Developer, mở lại kết nối hoặc chạy bất kỳ câu lệnh nào với user U1:
  ```sql
  SELECT * FROM SYS.NV;
  ```
- **Kết quả**: Oracle báo lỗi `ORA-28000: The account is locked; login denied.`

#### Demo 4: Mở khóa & Khôi phục trực tiếp từ Web Dashboard
- Trên giao diện Web Dashboard, tại dòng tài khoản **U1**, bấm nút **"Mở khóa User"**.
- Cầu nối sẽ tự động chạy lệnh `ALTER USER U1 ACCOUNT UNLOCK` trên Oracle.
- Tài khoản U1 trở lại trạng thái **OPEN** bình thường.
