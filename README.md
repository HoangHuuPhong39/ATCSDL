# 🛡️ HỆ THỐNG AN TOÀN CƠ SỞ DỮ LIỆU & PHÁT HIỆN / NGĂN CHẶN XÂM NHẬP (DB-IDS / DB-IPS) CHO ORACLE 23ai

Hệ thống giám sát, phát hiện và phản ứng an ninh CSDL theo mô hình **Phòng thủ đa tầng (Defense-in-Depth)** kết hợp giữa **Oracle 23ai Free**, **Cầu nối Telemetry Python (Bridge Daemon)** và **Web Dashboard quản trị trực quan thời gian thực (React + TypeScript + Tailwind CSS)**.

---

## 📑 MỤC LỤC
1. [Tổng quan kiến trúc & Tính năng](#-tổng-quan-kiến-trúc--tính-năng)
2. [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
3. [Yêu cầu hệ thống (Prerequisites)](#-yêu-cầu-hệ-thống-prerequisites)
4. [Hướng dẫn cài đặt chi tiết](#-hướng-dẫn-cài-đặt-chi-tiết)
5. [Hướng dẫn khởi động & Xác thực SOC](#-hướng-dẫn-khởi-động--xác-thực-soc)
6. [Kịch bản Demo chi tiết](#-kịch-bản-demo-chi-tiết)
7. [Cơ chế phản ứng an ninh (IPS Engine)](#-cơ-chế-phản-ứng-an-ninh-ips-engine)
8. [Kiểm thử tự động (Automated Tests)](#-kiểm-thử-tự-động-automated-tests)
9. [Xử lý sự cố thường gặp (Troubleshooting)](#-xử-lý-sự-cố-thường-gặp-troubleshooting)

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
- **Phản ứng tự động phân cấp (Tiered IPS)** (đồng bộ theo `shared/detection_policy.json`):
  - **Level 0 (Risk 0 - 19)**: Bình thường (Normal), không can thiệp.
  - **Level 1 (Risk 20 - 49)**: Cảnh báo, giám sát nâng cao (Low / Medium).
  - **Level 2 (Risk 50 - 79)**: Hạ quyền tạm thời (Privilege Containment) - Thu hồi quyền `INSERT/UPDATE/DELETE`, ép về chế độ **READ-ONLY**.
  - **Level 3 (Risk 80 - 100)**: Cô lập triệt để (Full Isolation) - Lập tức `ALTER USER ... ACCOUNT LOCK` và `ALTER SYSTEM KILL SESSION`.
- **Khôi phục 1-Click trên Web**: Quản trị viên SOC có thể bấm mở khóa tài khoản hoặc cấp lại quyền DML trực tiếp trên giao diện web.

---

## 📂 CẤU TRÚC THƯ MỤC

```
sqloracle/
├── dashboardweb/                 # [1] Ứng dụng SOC Web Dashboard hợp nhất (Port 3000)
│   ├── src/                     # Source code React (Giao diện, SocAuthGate, Biểu đồ, Heatmap)
│   ├── server.ts                # Backend Express trung gian kết nối API & Xác thực SOC
│   ├── package.json             # Danh sách thư viện & scripts (dev, start, test, lint, build)
│   ├── vite.config.ts           # Cấu hình Vite dev server
│   └── run_dashboard.bat        # Script khởi động riêng Web Dashboard
│
├── oracle/                       # [2] Thành phần CSDL & Cầu nối Telemetry (Backend API Port 8050)
│   ├── bridge.py                # Entrypoint HTTP JSON API & vòng lặp đồng bộ Oracle
│   ├── config.py                # Nạp cấu hình từ .env và shared/detection_policy.json
│   ├── db_client.py             # Kết nối Oracle (Thin mode mặc định / Thick mode tùy chọn)
│   ├── detector.py              # Phân tích chữ ký SQLi, SDB inference, Honeytoken & Risk Score
│   ├── ips_actions.py           # Thực thi phản ứng IPS (Revoke DML, Lock Account, Kill Session)
│   ├── state_store.py           # Lưu trạng thái cảnh báo & lịch sử IPS an toàn
│   ├── requirements.txt         # Thư viện Python (oracledb, python-dotenv...)
│   ├── SYS_FREEPDB1.sql         # Script khởi tạo Schema, Bẫy FGA, Triggers, Users
│   ├── DEMO_ALL_ATTACKS.sql     # 🔥 Bộ lệnh Demo toàn diện: Tấn công Kỹ thuật & Tấn công Suy diễn SDB
│   ├── DEMO_COMMANDS.sql        # Bộ lệnh mẫu thực thi các bài test tấn công
│   ├── User_U1.sql / User_U4.sql# Script hỗ trợ phân quyền kiểm thử
│   └── run_bridge.bat           # Script khởi động riêng Python Bridge
│
├── shared/
│   └── detection_policy.json    # Chính sách ngưỡng Risk Score, regex chữ ký & baseline dùng chung
├── .env.example                 # Mẫu file cấu hình biến môi trường (copy thành .env)
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

> **Ghi chú về `python-oracledb` (Thin vs Thick mode):**
> - Mặc định hệ thống chạy ở chế độ **Thin mode** (`ORACLE_CLIENT_MODE=thin`), thuần Python, **không cần cài Oracle Instant Client**.
> - Nếu môi trường yêu cầu tính năng mạng/xác thực nâng cao của Oracle Client, có thể chuyển sang **Thick mode** bằng cách đặt `ORACLE_CLIENT_MODE=thick` và khai báo đường dẫn thư viện tại `ORACLE_LIB_DIR` trong file `.env`.

### Bước 4: Khởi tạo Schema và Chính sách bảo mật trên Oracle Database

1. Mở **Oracle SQL Developer** (hoặc `sqlplus`).
2. Kết nối tới CSDL với quyền **SYSDBA**:
   - **Username**: `SYS`
   - **Role**: `SYSDBA`
   - **Password**: *(Mật khẩu cài đặt Oracle của bạn)*
   - **Service Name**: `FREEPDB1` (Cổng `1521`, Host `localhost`)
3. Khai báo mật khẩu mạnh (`>= 8` ký tự, không dùng mật khẩu yếu/placeholder cũ vì script sẽ từ chối với mã lỗi `ORA-20010`, không chứa dấu `"`) cho `U1`..`U4` qua `DEFINE` (hoặc dùng khối `ACCEPT` tương tác ở đầu script), rồi thực thi toàn bộ script **`oracle/SYS_FREEPDB1.sql`**:
   ```sql
   DEFINE u1_pass = 'StrongPass_U1#2026'
   DEFINE u2_pass = 'StrongPass_U2#2026'
   DEFINE u3_pass = 'StrongPass_U3#2026'
   DEFINE u4_pass = 'StrongPass_U4#2026'
   @oracle/SYS_FREEPDB1.sql
   ```
   - Script này sẽ tự động:
     - Tạo các User thử nghiệm: `U1`, `U2`, `U3`, `U4` với mật khẩu mạnh vừa khai báo (nếu User đã tồn tại từ trước thì giữ nguyên mật khẩu hiện có và chỉ thực hiện `ACCOUNT UNLOCK`).
     - Tạo bảng nhạy cảm `SYSTEM.NV` và Synonym `SYS.NV`.
     - Cài đặt bẫy Honeytoken (`NV_TRAP`).
     - Thiết lập Trigger nội sinh `SYS.TRG_PROTECT_NV` & bảng lưu vết vi phạm `SYS.IDS_TRIGGER_ALERTS`.
     - Cài đặt chính sách kiểm toán mịn `DBMS_FGA` (`FGA_HIGH_SALARY_ACCESS`, `FGA_HONEYTOKEN_TRAP`).
     - Bật chính sách kiểm toán hợp nhất `UNIFIED AUDIT`.

### Bước 5: Cấu hình biến môi trường qua file `.env`

Không chỉnh sửa mật khẩu trực tiếp trong mã nguồn Python. Tại thư mục gốc dự án, sao chép file mẫu `.env.example` thành `.env`:

```bash
# Windows (Command Prompt / PowerShell)
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Mở file `.env` vừa tạo và điền các giá trị phù hợp:

```dotenv
# Kết nối Oracle Database
ORACLE_USER=sys
ORACLE_PASSWORD=<Mật khẩu SYS Oracle của bạn>
ORACLE_DSN=localhost:1521/FREEPDB1
ORACLE_AUTH_MODE=sysdba
ORACLE_CLIENT_MODE=thin
# Nếu cần Thick mode, đổi thành thick và điền ORACLE_LIB_DIR=<đường dẫn Instant Client>

# Bridge JSON API (chỉ phục vụ API nội bộ, mặc định 127.0.0.1:8050)
BRIDGE_HOST=127.0.0.1
BRIDGE_PORT=8050

# Xác thực SOC Web Dashboard (Port 3000)
SOC_ADMIN_TOKEN=<Token bí mật của bạn; nếu để trống server sẽ tự sinh token tạm thời>
```

> **Lưu ý bảo mật:** File `.env` đã được khai báo trong `.gitignore`, không commit lên Git. Nếu để trống `SOC_ADMIN_TOKEN`, máy chủ Express sẽ tự sinh một token ngẫu nhiên cho phiên chạy hiện tại và in ra console lúc khởi động.

---

## 🚀 HƯỚNG DẪN KHỞI ĐỘNG & XÁC THỰC SOC

### Giao diện hợp nhất & Kiến trúc cổng kết nối
- **SOC Web Dashboard duy nhất**: Truy cập tại **`http://localhost:3000`** (React + Express). Đây là giao diện người dùng duy nhất cho giám sát, phân tích, chuyển đổi chế độ và thao tác IPS.
- **Python Bridge (`http://127.0.0.1:8050`)**: Chỉ đóng vai trò **Backend JSON API** nội bộ phục vụ đồng bộ dữ liệu và thực thi lệnh xuống Oracle, không phục vụ giao diện web riêng.

### Cách 1: Khởi động 1-Click (Khuyến nghị trên Windows)

Click đúp vào file **`CHAY_HE_THONG.bat`** tại thư mục gốc. Script sẽ tự động bật 2 cửa sổ console:
1. `Web Dashboard (React + Express)`: Chạy với biến `BRIDGE_MANAGED_EXTERNALLY=1` để không spawn trùng lặp tiến trình Bridge ngầm, phục vụ giao diện tại `http://localhost:3000`.
2. `Oracle Live Sync Bridge`: Chạy `python bridge.py` kết nối CSDL Oracle và mở JSON API nội bộ tại `http://127.0.0.1:8050`.

### Cách 2: Khởi động thủ công bằng dòng lệnh (Windows / Linux / macOS)

- **Tùy chọn A (Chạy chung 1 tiến trình từ `dashboardweb`)**: Khi `BRIDGE_MANAGED_EXTERNALLY=0` (mặc định trong `.env.example`), `server.ts` có thể tự quản lý tiến trình Bridge:
  ```bash
  cd dashboardweb
  npm run dev
  ```
- **Tùy chọn B (Chạy tách riêng 2 cửa sổ để dễ quan sát log)**:
  - Cửa sổ 1 (Oracle Bridge Backend API):
    ```bash
    cd oracle
    python bridge.py
    ```
  - Cửa sổ 2 (Web Dashboard — đặt `BRIDGE_MANAGED_EXTERNALLY=1` để tránh spawn trùng):
    ```bash
    cd dashboardweb
    # Windows CMD: set BRIDGE_MANAGED_EXTERNALLY=1 && npm run dev
    # Linux/macOS: BRIDGE_MANAGED_EXTERNALLY=1 npm run dev
    ```

### Xác thực `SOC_ADMIN_TOKEN` & Chế độ Live Oracle vs Simulator
1. Mở trình duyệt tới **`http://localhost:3000`**.
2. Tại màn hình **SOC GATE**, nhập giá trị **`SOC_ADMIN_TOKEN`** đã đặt trong `.env` (hoặc copy token tạm thời được in trong log `[SOC AUTH] Generated ephemeral SOC_ADMIN_TOKEN: ...` trên console của Web Dashboard). Phiên đăng nhập được bảo vệ bằng cookie `HttpOnly` và `X-CSRF-Token`.
3. Sau khi mở khóa Dashboard, bạn có thể chuyển đổi giữa 2 chế độ nguồn dữ liệu ngay trên giao diện:
   - **Live Oracle**: Đồng bộ trực tiếp dữ liệu kiểm toán thực tế, Risk Score và thực thi lệnh IPS (Lock/Unlock, Revoke/Restore DML) xuống Oracle Database thông qua `bridge.py`.
   - **Simulator**: Chế độ mô phỏng kịch bản tấn công ngay trên Web để kiểm thử giao diện hoặc trình diễn khi chưa kết nối Oracle Database.

---

## 🎯 KỊCH BẢN DEMO CHI TIẾT

Mở **Oracle SQL Developer**, tạo kết nối với user **`U1`** (Password: `<mật khẩu mạnh bạn đã khai báo khi chạy SYS_FREEPDB1.sql>`, Service Name: `FREEPDB1`), sau đó thực hiện theo các kịch bản dưới đây trong file `oracle/DEMO_COMMANDS.sql`:

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

Ngưỡng đánh giá Risk Score được đồng bộ tập trung tại `shared/detection_policy.json` cho cả Python Bridge và Web Dashboard:

| Cấp độ (Level) | Risk Score | Phân loại | Hành động tự động của IPS | Trạng thái hiển thị |
| :---: | :---: | :---: | :--- | :---: |
| **Level 0** | 0 - 19 | **NORMAL** | Hoạt động bình thường, không can thiệp. | Xanh lá |
| **Level 1** | 20 - 49 | **LOW / MEDIUM** | Cảnh báo giám sát, ghi nhận lịch sử audit. | Vàng / Cam |
| **Level 2** | 50 - 79 | **HIGH** | **Hạ quyền tạm thời**: `REVOKE INSERT, UPDATE, DELETE`, ép về chế độ chỉ đọc. | Đỏ cam (Read-Only) |
| **Level 3** | 80 - 100 | **CRITICAL** | **Cách ly triệt để**: `ALTER USER ... ACCOUNT LOCK` và `ALTER SYSTEM KILL SESSION`. | Đỏ đậm (LOCKED) |

---

## 🧪 KIỂM THỬ TỰ ĐỘNG (AUTOMATED TESTS)

### 1. Kiểm thử Frontend & Backend Node.js (`dashboardweb`)
```bash
cd dashboardweb
npm run lint
npm test
npm run build
```

### 2. Kiểm thử Python Bridge & Detection Engine
Chạy từ thư mục gốc repository:
```bash
python -m unittest discover -s oracle/tests -t . -v
```
Hoặc chạy trực tiếp bên trong thư mục `oracle`:
```bash
cd oracle
python -m unittest discover -s tests -v
```

---

## ❓ XỬ LÝ SỰ CỐ THƯỜNG GẶP (TROUBLESHOOTING)

1. **Lỗi `ORA-01017: invalid username/password` khi chạy `bridge.py`**:
   - Kiểm tra file `.env` ở thư mục gốc và đảm bảo biến `ORACLE_PASSWORD` (cùng `ORACLE_USER`, `ORACLE_AUTH_MODE`) khớp với mật khẩu tài khoản `sys` trên Oracle Database của bạn.
2. **Lỗi `ORA-12541: TNS:no listener` hoặc không kết nối được DB**:
   - Kiểm tra dịch vụ Oracle Service và Oracle Listener đã chạy trong `services.msc`.
   - Đảm bảo `ORACLE_DSN` trong `.env` đúng Service Name: `localhost:1521/FREEPDB1` (Oracle 23ai Free) hoặc `localhost:1521/XEPDB1` (Oracle XE).
3. **Cần dùng Oracle Instant Client (Thick mode)**:
   - Mặc định Bridge dùng Thin mode (`ORACLE_CLIENT_MODE=thin`). Nếu gặp lỗi yêu cầu Thick mode (ví dụ kiểu xác thực hoặc cipher cũ), đặt `ORACLE_CLIENT_MODE=thick` và trỏ `ORACLE_LIB_DIR` tới thư mục Oracle Instant Client trong `.env`.
4. **Không đăng nhập được SOC Dashboard hoặc quên `SOC_ADMIN_TOKEN`**:
   - Kiểm tra giá trị `SOC_ADMIN_TOKEN` trong `.env`. Nếu bạn để trống biến này trong `.env`, xem log console khởi động của `dashboardweb` (`[SOC AUTH] Generated ephemeral SOC_ADMIN_TOKEN: ...`) để lấy token cho phiên chạy hiện tại.
5. **Web Dashboard báo lỗi kết nối Bridge hoặc xung đột cổng `8050`**:
   - Lưu ý `http://localhost:3000` là giao diện web duy nhất; cổng `8050` chỉ phục vụ backend JSON API của `bridge.py`.
   - Nếu chạy `bridge.py` ở cửa sổ riêng, hãy đặt `BRIDGE_MANAGED_EXTERNALLY=1` cho `dashboardweb` (như `CHAY_HE_THONG.bat` đã cấu hình) để tránh `server.ts` spawn thêm một tiến trình `bridge.py` trùng cổng `8050`.
6. **Không thấy bản ghi kiểm toán cập nhật ngay**:
   - Đảm bảo Dashboard đang ở chế độ **Live Oracle** (không phải **Simulator**), bấm nút **"Làm mới dữ liệu (Flush Audit)"** trên Dashboard hoặc chạy lệnh `EXEC DBMS_AUDIT_MGMT.FLUSH_UNIFIED_AUDIT_TRAIL;` để xả đệm RAM kiểm toán của Oracle xuống bảng vật lý.

---

## 👥 TÁC GIẢ & BẢN QUYỀN
- Đề tài: An toàn Cơ sở dữ liệu & Phát hiện xâm nhập Oracle 23ai.
- Repository: [HoangHuuPhong39/ATCSDL](https://github.com/HoangHuuPhong39/ATCSDL.git)
