# KỊCH BẢN ĐỒNG BỘ & DEMO HỆ THỐNG AN TOÀN CSDL (ORACLE 23ai + WEB DASHBOARD)

## Cấu trúc thư mục dự án (tại thư mục gốc repository):
- `dashboardweb/`: Giao diện SOC Web Dashboard duy nhất giám sát an ninh CSDL thời gian thực (React + Express, cổng `3000`).
- `oracle/`: Dữ liệu Oracle, các script SQL (`DEMO_COMMANDS.sql`, `SYS_FREEPDB1.sql`) và Cầu nối đồng bộ tự động `bridge.py` (cung cấp JSON API nội bộ tại cổng `8050`).
- `shared/detection_policy.json`: Chính sách ngưỡng Risk Score, chữ ký tấn công và quy tắc IPS dùng chung.
- `.env.example`: Mẫu biến môi trường (copy thành `.env` tại thư mục gốc để cấu hình `ORACLE_PASSWORD`, `SOC_ADMIN_TOKEN`).
- `CHAY_HE_THONG.bat`: File khởi động 1-click tự động bật cả Web Dashboard và Cầu nối Oracle.

---

## CƠ CHẾ HOẠT ĐỘNG ĐỒNG BỘ:
1. **Oracle Database (Oracle 23ai Free)**: Chạy dịch vụ tại `localhost:1521/FREEPDB1`.
2. **Cầu nối `bridge.py` (Backend JSON API - Port `8050`)**:
   - Đọc cấu hình từ `.env` ở thư mục gốc (`ORACLE_USER`, `ORACLE_PASSWORD`, `ORACLE_DSN`, `ORACLE_CLIENT_MODE`) và chính sách từ `shared/detection_policy.json`.
   - Tự động kết nối vào Oracle 23ai với quyền quản trị SYSDBA.
   - Định kỳ mỗi 2 giây gọi lệnh xả bộ nhớ kiểm toán `DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL`.
   - Quét bảng `UNIFIED_AUDIT_TRAIL`, `SYS.IDS_TRIGGER_ALERTS`, `DBA_USERS` và `SYS.NV`.
   - Đẩy dữ liệu vi phạm sang Web Dashboard (`http://localhost:3000/api/oracle-sync`) và cung cấp API trạng thái tại `http://127.0.0.1:8050`.
3. **Web Dashboard (`http://localhost:3000`)**:
   - Giao diện quản trị SOC hợp nhất duy nhất; được bảo vệ bởi `SOC_ADMIN_TOKEN` (qua cookie `HttpOnly` và `X-CSRF-Token`).
   - Hỗ trợ chuyển đổi giữa chế độ **Live Oracle** (dữ liệu thật từ `bridge.py`) và **Simulator** (dữ liệu mô phỏng khi chưa kết nối DB).
   - Hiển thị trực quan biểu đồ nhiệt, chuông báo, bản ghi vi phạm, tính Risk Score (`0 -> 100`) và trạng thái User (`LOCKED`, `READ-ONLY`).
   - Khi bấm nút "Mở khóa User" hoặc "Khôi phục quyền DML" trên Web, lệnh sẽ được cầu nối gửi ngược lại và thực thi trực tiếp trên Oracle!

---

## CÁC BƯỚC THỰC HIỆN KHI DEMO CHO GIÁO VIÊN:

### Bước 0: Cấu hình `.env` (chỉ cần làm lần đầu)
- Tại thư mục gốc dự án, sao chép file `.env.example` thành `.env`:
  ```bash
  copy .env.example .env
  ```
- Mở `.env` và điền:
  - `ORACLE_PASSWORD`: Mật khẩu tài khoản `sys` trên Oracle Database của bạn.
  - `SOC_ADMIN_TOKEN`: Token đăng nhập SOC Web Dashboard (nếu để trống, server sẽ tự sinh token tạm thời và in ra màn hình console khi khởi động).

### Bước 1: Khởi động hệ thống & Đăng nhập SOC Dashboard
- Tại thư mục gốc dự án, click đúp vào file **`CHAY_HE_THONG.bat`** (hoặc chạy thủ công `bridge.py` và `npm run dev` trong `dashboardweb`).
- Mở trình duyệt truy cập giao diện duy nhất: **`http://localhost:3000`** *(Lưu ý: cổng `8050` chỉ phục vụ JSON API cho `bridge.py`, không phải giao diện web)*.
- Tại màn hình **SOC GATE**, nhập mã **`SOC_ADMIN_TOKEN`** đã cấu hình trong `.env` (hoặc copy token tạm thời từ cửa sổ console của Web Dashboard) để mở khóa bảng điều khiển.
- Trên thanh Header của Web Dashboard, kiểm tra trạng thái đang ở chế độ **Live Oracle** (hoặc **"Oracle Live Sync: ON"** sáng màu xanh lá). Nếu đang ở chế độ **Simulator**, mở phần cấu hình Bridge trên giao diện để chuyển sang **Live Oracle**.

### Bước 2: Mở Oracle SQL Developer để Demo
Mở kết nối tới Oracle (user `U1`, password `<mật khẩu mạnh bạn đã khai báo khi chạy SYS_FREEPDB1.sql>`, Service `FREEPDB1`).
*(Lưu ý: Trước khi chạy `oracle/SYS_FREEPDB1.sql` lần đầu, cần khai báo mật khẩu mạnh `>= 8` ký tự cho `U1`..`U4` qua `DEFINE u1_pass..u4_pass` hoặc `ACCEPT`; mật khẩu yếu mặc định cũ bị script chặn với `ORA-20010`.)*

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
