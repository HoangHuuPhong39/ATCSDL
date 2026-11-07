# 🛡️ HỆ THỐNG AN TOÀN CƠ SỞ DỮ LIỆU & PHÁT HIỆN / NGĂN CHẶN XÂM NHẬP (DB-IDS / DB-IPS) CHO ORACLE 23ai

Hệ thống giám sát, phát hiện và phản ứng an ninh CSDL theo mô hình **Phòng thủ đa tầng (Defense-in-Depth)** kết hợp giữa **Oracle 23ai Free**, **Cầu nối Telemetry Python (Bridge Daemon)** và **Web Dashboard quản trị trực quan thời gian thực (React + TypeScript + Tailwind CSS)**.

---

## 📑 MỤC LỤC
1. [Tổng quan kiến trúc & Tính năng](#-tổng-quan-kiến-trúc--tính-năng)
2. [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
3. [Yêu cầu hệ thống (Prerequisites)](#-yêu-cầu-hệ-thống-prerequisites)
4. [Hướng dẫn cài đặt chi tiết](#-hướng-dẫn-cài-đặt-chi-tiết)
5. [Hướng dẫn khởi động hệ thống](#-hướng-dẫn-khởi-động-hệ-thống)
6. [Kịch bản Demo chi tiết](#-kịch-bản-demo-chi-tiết)
7. [Cơ chế phản ứng an ninh (IPS Engine)](#-cơ-chế-phản-ứng-an-ninh-ips-engine)
8. [Xử lý sự cố thường gặp (Troubleshooting)](#-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## 🏛️ TỔNG QUAN KIẾN TRÚC & TÍNH NĂNG

Hệ thống được thiết kế theo mô hình phòng thủ 3 tầng:

```
[ Oracle Database 23ai ]
  │  ├── Autonomous Triggers (Chặn gian lận, tăng lương bất thường > 50%)
  │  ├── Fine-Grained Auditing (DBMS_FGA) & Honeytoken Trap (NV_TRAP)
  │  ├── Unified Audit Trail & V$SQL Query Inspection
  │  └── Dynamic User Containment (Revoke DML / Lock Account)
  ▼ (Polling mỗi 2-3s qua sys.DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL)
[ Python Sync Bridge (bridge.py) ]
  │  ├── Tính toán Risk Score động (0 - 100) theo mô hình Bayesian / Heuristic
  │  ├── Phân tích chữ ký SQL Injection & Tấn công suy diễn thống kê (Tracker Queries)
  │  ├── Kích hoạt IPS tự động (Auto-Response): Khóa User, Thu hồi quyền DML
  │  └── Cung cấp REST API & Nhận lệnh phản hồi từ Web
  ▼ (HTTP / WebSocket Telemetry)
[ Web Dashboard (React + Vite + Express - Port 3000) ]
  ├── Bản đồ ma trận đe dọa (Security Heatmap)
  ├── Đồng hồ đo Risk Score & Chuông cảnh báo âm thanh
  ├── Nhật ký chi tiết vi phạm (Audit Trail, Triggers, Honeytoken, Brute-Force)
  └── Bảng điều khiển can thiệp khẩn cấp: Mở khóa User, Phục hồi quyền DML
```

### ✨ Các tính năng nổi bật:
- **Autonomous Database Trigger**: Tự động ngắt các thao tác DML trái phép (ví dụ: xoá dữ liệu nhân sự, tăng lương nhảy vọt > 50%) và ghi vết độc lập vào `SYS.IDS_TRIGGER_ALERTS` ngay cả khi giao dịch chính bị `ROLLBACK`.
- **Bẫy Honeytoken (Deception Technology)**: Cài đặt bản ghi nhân viên ảo (`NV_TRAP`). Bất kỳ truy vấn nào chạm vào bản ghi này sẽ ngay lập tức bị quy kết là hành vi do thám/dump dữ liệu trái phép, lập tức cô lập tài khoản.
- **Phát hiện SQL Injection & Suy diễn thống kê (Inference Attack)**: Phân tích cú pháp SQL trên `V$SQL` và `Unified Audit` để phát hiện payload bypass (`OR 1=1`, `UNION SELECT`) và chuỗi câu lệnh thống kê (`COUNT`, `AVG`, `SUM`) nhằm dò tìm dữ liệu nhạy cảm.
- **Phản ứng tự động phân cấp (Tiered IPS)**:
  - **Level 1 (Risk 0-40)**: Cảnh báo, giám sát nâng cao.
  - **Level 2 (Risk 41-75)**: Hạ quyền tạm thời (Privilege Containment) - Thu hồi quyền `INSERT/UPDATE/DELETE`, ép về chế độ **READ-ONLY**.
  - **Level 3 (Risk 76-100)**: Cô lập triệt để (Full Isolation) - Lập tức `ALTER USER ... ACCOUNT LOCK` và `ALTER SYSTEM KILL SESSION`.
- **Khôi phục 1-Click trên Web**: Quản trị viên SOC có thể bấm mở khóa tài khoản hoặc cấp lại quyền DML trực tiếp trên giao diện web.

---

## 📂 CẤU TRÚC THƯ MỤC

```
sqloracle/
├── dashboardweb/                 # [1] Ứng dụng Web Dashboard
│   ├── src/                     # Source code React (Giao diện, Biểu đồ, Heatmap)
│   ├── server.ts                # Backend Express trung gian kết nối API
│   ├── package.json             # Danh sách thư viện Node.js
│   ├── vite.config.ts           # Cấu hình Vite dev server
│   └── run_dashboard.bat        # Script khởi động riêng Web Dashboard
│
├── oracle/                       # [2] Thành phần CSDL & Cầu nối Telemetry
│   ├── bridge.py                # Cầu nối phân tích kiểm toán, tính Risk Score & IPS
│   ├── requirements.txt         # Thư viện Python (oracledb)
│   ├── SYS_FREEPDB1.sql         # Script khởi tạo Schema, Bẫy FGA, Triggers, Users
│   ├── DEMO_COMMANDS.sql        # Bộ lệnh mẫu thực thi các bài test tấn công
│   ├── User_U1.sql / User_U4.sql# Script hỗ trợ phân quyền kiểm thử
│   └── run_bridge.bat           # Script khởi động riêng Python Bridge
│
├── CHAY_HE_THONG.bat            # 🚀 File chạy 1-Click khởi động toàn bộ hệ thống
├── HUONG_DAN_DEMO.md            # Hướng dẫn demo nhanh tóm tắt
└── README.md                    # Tài liệu hướng dẫn sử dụng & triển khai
```

---

## 💻 YÊU CẦU HỆ THỐNG (PREREQUISITES)

1. **Hệ điều hành**: Windows 10/11 hoặc Windows Server (hỗ trợ Linux/macOS khi chạy lệnh tương đương).
2. **Oracle Database**: Oracle Database 23ai Free (khuyến nghị) hoặc 21c/19c (Pluggable Database: `FREEPDB1` hoặc `XEPDB1`).
3. **Python**: Python 3.9 trở lên (đã tích hợp vào biến môi trường `PATH`).
4. **Node.js**: Phiên bản 18.x trở lên cùng `npm`.
5. **Công cụ SQL**: Oracle SQL Developer, DBeaver, VS Code Oracle Developer Tools hoặc `sqlplus`.

---

## 🛠️ HƯỚNG DẪN CÀI ĐẶT CHI TIẾT

### Bước 1: Clone kho mã nguồn về máy

```bash
git clone https://github.com/HoangHuuPhong39/ATCSDL.git
cd ATCSDL
```

### Bước 2: Cài đặt phụ thuộc cho Web Dashboard

Mở Command Prompt hoặc Terminal tại thư mục `dashboardweb`:

```bash
cd dashboardweb
npm install
cd ..
```

### Bước 3: Cài đặt thư viện Python cho Cầu nối Oracle

Mở Command Prompt hoặc Terminal tại thư mục `oracle`:

```bash
cd oracle
pip install -r requirements.txt
cd ..
```

> **Ghi chú về thư viện `oracledb`:** Thư viện chạy mặc định ở chế độ **Thin mode** (thuần Python), không bắt buộc phải cài đặt Oracle Instant Client cồng kềnh.

### Bước 4: Khởi tạo Schema và Chính sách bảo mật trên Oracle Database

1. Mở **Oracle SQL Developer** (hoặc `sqlplus`).
2. Kết nối tới CSDL với quyền **SYSDBA**:
   - **Username**: `SYS`
   - **Role**: `SYSDBA`
   - **Password**: *(Mật khẩu cài đặt Oracle của bạn)*
   - **Service Name**: `FREEPDB1` (Cổng `1521`, Host `localhost`)
3. Mở và thực thi toàn bộ script: **`oracle/SYS_FREEPDB1.sql`**.
   - Script này sẽ tự động:
     - Tạo các User thử nghiệm: `U1`, `U2`, `U3`, `U4` (Mật khẩu lần lượt: `U1123`, `U2123`, `U3123`, `U4123`).
     - Tạo bảng nhạy cảm `SYSTEM.NV` và Synonym `SYS.NV`.
     - Cài đặt bẫy Honeytoken (`NV_TRAP`).
     - Thiết lập Trigger nội sinh `SYS.TRG_PROTECT_NV` & bảng lưu vết vi phạm `SYS.IDS_TRIGGER_ALERTS`.
     - Cài đặt chính sách kiểm toán mịn `DBMS_FGA` (`FGA_HIGH_SALARY_ACCESS`, `FGA_HONEYTOKEN_TRAP`).
     - Bật chính sách kiểm toán hợp nhất `UNIFIED AUDIT`.

### Bước 5: Cấu hình mật khẩu kết nối CSDL trong Bridge

Mở file **`oracle/bridge.py`**, kiểm tra các dòng 30-33:

```python
# ================= CẤU HÌNH KẾT NỐI ORACLE =================
DB_USER = "sys"
DB_PASS = "123456"                 # Điền đúng mật khẩu SYS trên máy bạn
DB_DSN  = "localhost:1521/FREEPDB1" # Sửa thành XEPDB1 nếu dùng bản XE
PORT    = 8050
```

---

## 🚀 HƯỚNG DẪN KHỞI ĐỘNG HỆ THỐNG

### Cách 1: Khởi động 1-Click (Khuyến nghị trên Windows)

Chỉ cần click đúp vào file **`CHAY_HE_THONG.bat`** tại thư mục gốc. Hệ thống sẽ tự động bật 2 cửa sổ console:
1. `Web Dashboard`: Khởi chạy Web tại `http://localhost:3000`.
2. `Oracle Live Sync Bridge`: Kết nối CSDL Oracle và lắng nghe tại `http://localhost:8050`.

### Cách 2: Khởi động thủ công bằng dòng lệnh

- **Cửa sổ 1 (Web Dashboard)**:
  ```bash
  cd dashboardweb
  npm run dev
  ```
  *(Truy cập trình duyệt: `http://localhost:3000`)*

- **Cửa sổ 2 (Oracle Bridge Daemon)**:
  ```bash
  cd oracle
  python bridge.py
  ```

---

## 🎯 KỊCH BẢN DEMO CHI TIẾT

Mở **Oracle SQL Developer**, tạo kết nối với user **`U1`** (Password: `U1123`, Service Name: `FREEPDB1`), sau đó thực hiện theo các kịch bản dưới đây trong file `oracle/DEMO_COMMANDS.sql`:

### 🧪 Kịch bản 1: Trigger chặn gian lận dữ liệu tức thời (Autonomous Trigger)
- **Hành động**: Thử cập nhật tăng lương nhân viên vượt 50%:
  ```sql
  UPDATE SYS.NV SET luong = 5000 WHERE manv = 'NV1';
  ```
- **Kết quả trên Oracle**: Bị chặn đứng với mã lỗi `ORA-20002: Luong tang vuot nguong cho phep (> 50%)`.
- **Kết quả trên Web Dashboard**: Ngay lập tức chuông báo kêu, hiển thị cảnh báo đỏ tại tab **Triggers**, Risk Score của `U1` tự động tăng.

---

### 🧪 Kịch bản 2: Kiểm toán FGA & Bẫy dữ liệu Honeytoken (Auto-Lock IPS)
- **Hành động**: Kẻ tấn công thực hiện quét trộm bảng nhân sự và vô tình đọc bản ghi bẫy `NV_TRAP`:
  ```sql
  SELECT * FROM SYS.NV WHERE manv = 'NV_TRAP';
  ```
- **Kết quả trên Web Dashboard**:
  - Bẫy `FGA_HONEYTOKEN_TRAP` lập tức kích hoạt.
  - Risk Score nhảy vọt lên mức tối đa **95 / 100** (Level 3 - CRITICAL).
  - IPS Engine tự động kích hoạt: Tài khoản `U1` bị chuyển sang trạng thái **LOCKED**.
- **Kiểm chứng trên Oracle**: Thực thi bất kỳ câu lệnh nào bằng user `U1`:
  ```sql
  SELECT * FROM SYS.NV;
  ```
  Oracle sẽ phản hồi lỗi: `ORA-28000: The account is locked; login denied.`

---

### 🧪 Kịch bản 3: Tấn công suy diễn thống kê & Phản ứng hạ quyền (Read-Only)
- **Hành động**: Chạy liên tiếp các truy vấn thống kê nhằm suy diễn mức lương mục tiêu:
  ```sql
  SELECT COUNT(*), AVG(luong) FROM SYS.NV WHERE gioitinh = 'Nam';
  SELECT SUM(luong), MAX(luong) FROM SYS.NV WHERE gioitinh = 'Nam' AND luong < 5000;
  SELECT COUNT(*), SUM(luong) FROM SYS.NV WHERE gioitinh = 'Nam' AND manv != 'NV1' AND luong < 5000;
  SELECT AVG(luong), MIN(luong) FROM SYS.NV WHERE luong >= 1000 AND luong < 5000;
  ```
- **Kết quả**:
  - Hệ thống phát hiện Statistical Inference Attack.
  - Đánh giá vi phạm Level 2: Hệ thống tự động thu hồi quyền `INSERT/UPDATE/DELETE`, ép tài khoản `U1` về chế độ **READ-ONLY**.
  - `U1` vẫn `SELECT` được bình thường nhưng mọi lệnh ghi (`UPDATE SYS.NV ...`) sẽ bị lỗi `ORA-01031: insufficient privileges`.

---

### 🧪 Kịch bản 4: Phát hiện mã độc SQL Injection
- **Hành động**: Thực thi truy vấn chứa mệnh đề bypass kinh điển:
  ```sql
  SELECT * FROM SYS.NV WHERE manv = 'NV1' OR 1=1;
  ```
- **Kết quả**: Hệ thống phân tích cú pháp SQL từ `V$SQL`, gắn cờ SQL Injection Signature, nâng Risk Score lên mức nguy hiểm.

---

### 🧪 Kịch bản 5: Khôi phục và Mở khóa 1-Click từ Web Dashboard
- Sau khi `U1` bị khóa hoặc bị hạ quyền:
  1. Trên giao diện Web Dashboard (`http://localhost:3000`), tìm dòng tài khoản **`U1`**.
  2. Bấm nút **"Mở khóa User"** hoặc **"Khôi phục quyền DML"**.
  3. Cầu nối tự động gửi lệnh `ALTER USER U1 ACCOUNT UNLOCK` / `GRANT ...` tới Oracle.
  4. Tài khoản `U1` hoạt động bình thường trở lại ngay lập tức mà không cần gõ lệnh thủ công trong console DB!

---

## 🛡️ CƠ CHẾ PHẢN ỨNG AN NINH (IPS ENGINE)

| Cấp độ (Level) | Risk Score | Phân loại | Hành động tự động của IPS | Trạng thái hiển thị |
| :---: | :---: | :---: | :--- | :---: |
| **Level 0** | 0 - 20 | **NORMAL** | Hoạt động bình thường, không can thiệp. | Xanh lá |
| **Level 1** | 21 - 45 | **LOW / MEDIUM** | Cảnh báo giám sát, ghi nhận lịch sử audit. | Vàng / Cam |
| **Level 2** | 46 - 75 | **HIGH** | **Hạ quyền tạm thời**: `REVOKE INSERT, UPDATE, DELETE`, ép về chế độ chỉ đọc. | Đỏ cam (Read-Only) |
| **Level 3** | 76 - 100 | **CRITICAL** | **Cách ly triệt để**: `ALTER USER ... ACCOUNT LOCK` và `ALTER SYSTEM KILL SESSION`. | Đỏ đậm (LOCKED) |

---

## ❓ XỬ LÝ SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

1. **Lỗi `ORA-01017: invalid username/password` khi chạy `bridge.py`**:
   - Mở `oracle/bridge.py` và sửa `DB_PASS` khớp với mật khẩu tài khoản `sys` trên máy tính của bạn.
2. **Lỗi `ORA-12541: TNS:no listener` hoặc không kết nối được DB**:
   - Kiểm tra dịch vụ Oracle Service và Oracle Listener đã chạy trong `services.msc`.
   - Đảm bảo Service Name là `FREEPDB1` (đối với Oracle 23ai Free) hoặc `XEPDB1` (đối với bản XE).
3. **Web Dashboard báo lỗi kết nối Bridge hoặc Sync OFF**:
   - Đảm bảo `bridge.py` đang chạy ở cửa sổ dòng lệnh thứ hai (Port 8050).
   - Kiểm tra xem cổng 8050 hoặc cổng 3000 có bị phần mềm diệt virus/firewall chặn không.
4. **Không thấy bản ghi kiểm toán cập nhật ngay**:
   - Bấm nút **"Làm mới dữ liệu (Flush Audit)"** trên Dashboard hoặc chạy lệnh `EXEC DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL;` để xả đệm RAM kiểm toán của Oracle xuống bảng vật lý.

---

## 👥 TÁC GIẢ & BẢN QUYỀN
- Đề tài: An toàn Cơ sở dữ liệu & Phát hiện xâm nhập Oracle 23ai.
- Repository: [HoangHuuPhong39/ATCSDL](https://github.com/HoangHuuPhong39/ATCSDL.git)
