import React, { useState } from 'react';
import { 
  BookOpen, 
  Shield, 
  Layers, 
  Zap, 
  Target, 
  FileCode, 
  Lock, 
  Cpu, 
  Copy, 
  Check,
  Database,
  Calculator
} from 'lucide-react';

export const DocsTab: React.FC = () => {
  const [activeSection, setActiveSection] = useState<string>('taxonomy');
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  const handleCopy = (snippetKey: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippet(snippetKey);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  const sections = [
    { id: 'taxonomy', title: '1. Hệ thống Phân loại Tấn công DBMS & SDB', icon: Database },
    { id: 'sdb_math', title: '2. Mô hình Toán học Tấn công Suy diễn SDB', icon: Calculator },
    { id: 'architecture', title: '3. Kiến trúc Phòng thủ Chiều sâu (5 Tầng)', icon: Layers },
    { id: 'trigger', title: '4. Cơ chế Trigger Tự trị (Autonomous Transaction)', icon: Zap },
    { id: 'honeytoken', title: '5. Bẫy dữ liệu Honeytoken & DBMS_FGA', icon: Target },
    { id: 'detection', title: '6. Động cơ Nhận diện & Chấm điểm Rủi ro', icon: Cpu },
    { id: 'ips', title: '7. Phản ứng Đa cấp Chủ động (Active IPS)', icon: Lock },
    { id: 'plsql', title: '8. Kịch bản PL/SQL Triển khai trên Oracle 23ai', icon: FileCode },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {/* Table of contents sidebar */}
      <div className="space-y-2 lg:sticky lg:top-20 self-start">
        <div className="text-[11.5px] font-bold text-slate-400 uppercase tracking-wider px-2">
          Nội dung Đề tài &amp; Kỹ thuật
        </div>
        <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-2 space-y-1">
          {sections.map((sec) => {
            const Icon = sec.icon;
            const isActive = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                onClick={() => setActiveSection(sec.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left text-[12px] font-semibold transition-all cursor-pointer ${
                  isActive
                    ? 'bg-sky-600/20 text-sky-300 border border-sky-400/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#131e33]'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                <span className="truncate">{sec.title}</span>
              </button>
            );
          })}
        </div>

        {/* Quick specs box */}
        <div className="bg-[#0b1322] border border-white/5 rounded-xl p-3 text-[11.5px] space-y-2">
          <div className="font-bold text-slate-300 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span>Thông số Hệ thống</span>
          </div>
          <div className="text-slate-400 space-y-1 font-mono text-[11px]">
            <div>• Database: Oracle 23ai Free PDB</div>
            <div>• DSN: localhost:1521/FREEPDB1</div>
            <div>• DBMS Attacks: 5 nhóm kỹ thuật</div>
            <div>• SDB Inference: 4 kiểu suy diễn</div>
            <div>• IPS Levels: 0, 1, 2, 3 (Containment)</div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="lg:col-span-3 space-y-6">
        {/* Section 1: Full Taxonomy of DBMS & SDB Attacks */}
        {activeSection === 'taxonomy' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-5">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Database className="w-5 h-5 text-sky-400" />
              <h2 className="text-[16px] font-bold text-slate-100">
                1. Hệ thống Phân loại Toàn diện Các Dạng Tấn công vào DBMS &amp; CSDL Thống kê (SDB)
              </h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-4 leading-relaxed">
              <p>
                Hệ thống IDS/IPS trong đề tài được thiết kế để nhận diện và phòng chống toàn bộ <strong>2 đại phân nhóm tấn công cơ sở dữ liệu</strong> theo đúng chuẩn lý thuyết An toàn Cơ sở dữ liệu:
              </p>

              {/* Group A: Technical Attacks on DBMS & Apps */}
              <div className="space-y-3">
                <h3 className="font-bold text-red-300 text-[14px] flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-red-500/20 border border-red-500/40 font-mono text-[11px]">PHÂN NHÓM I</span>
                  <span>Các Dạng Tấn công Kỹ thuật vào DBMS &amp; Ứng dụng (5 Kỹ thuật)</span>
                </h3>

                <div className="grid grid-cols-1 gap-3">
                  <div className="bg-[#0b1322] border border-red-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">1. SQL Injection (Chèn mã độc SQL)</h4>
                      <span className="font-mono text-[11px] text-red-400 font-bold">Risk Score: 95 (Level 3)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      <strong>Bản chất:</strong> Chèn mã độc hại vào tham số đầu vào làm thay đổi cấu trúc cú pháp câu lệnh SQL ban đầu (tautology <code className="text-sky-300 font-mono">OR 1=1</code>, nối bảng <code className="text-sky-300 font-mono">UNION SELECT</code>, ngắt dòng <code className="text-sky-300 font-mono">--</code> hoặc gọi gói hệ thống <code className="text-sky-300 font-mono">UTL_HTTP</code>).
                    </p>
                    <div className="text-[11px] text-emerald-400 mt-1 font-mono">
                      → Cơ chế bắt: SQLi Signature Regex Engine trên UNIFIED_AUDIT_TRAIL + DBMS_FGA.
                    </div>
                  </div>

                  <div className="bg-[#0b1322] border border-amber-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">2. Giả mạo / Giả danh (Masquerading Attack)</h4>
                      <span className="font-mono text-[11px] text-amber-400 font-bold">Risk Score: 75 (Level 2)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      <strong>Bản chất:</strong> Kẻ tấn công đánh cắp thông tin đăng nhập hợp pháp (Username/Password hoặc Session Token) của nhân viên để truy cập CSDL dưới danh nghĩa hợp lệ.
                    </p>
                    <div className="text-[11px] text-emerald-400 mt-1 font-mono">
                      → Cơ chế bắt: Đối chiếu hồ sơ ngữ cảnh phiên (Contextual Profiling) qua bộ 3 trường <code className="text-sky-300">OS_USERNAME</code>, <code className="text-sky-300">USERHOST</code> và <code className="text-sky-300">CLIENT_PROGRAM_NAME</code>.
                    </div>
                  </div>

                  <div className="bg-[#0b1322] border border-red-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">3. Leo thang đặc quyền (Privilege Escalation)</h4>
                      <span className="font-mono text-[11px] text-red-400 font-bold">Risk Score: 88 (Level 3)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      <strong>Bản chất:</strong> Tìm cách nâng cao quyền truy cập vượt quá mức được cấp (Vertical/Horizontal Escalation) bằng các lệnh <code className="text-sky-300 font-mono">GRANT DBA</code>, <code className="text-sky-300 font-mono">ALTER USER</code>, <code className="text-sky-300 font-mono">CREATE USER</code> hoặc lạm dụng thủ tục có quyền <code className="text-sky-300 font-mono">DEFINER</code>.
                    </p>
                    <div className="text-[11px] text-emerald-400 mt-1 font-mono">
                      → Cơ chế bắt: Chính sách Unified Audit <code className="text-sky-300">ids_priv_abuse_pol</code> + Autonomous Trigger <code className="text-sky-300">SYS.TRG_PROTECT_NV</code>.
                    </div>
                  </div>

                  <div className="bg-[#0b1322] border border-red-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">4. Tấn công đăng nhập thất bại (Failed Logins / Brute-Force)</h4>
                      <span className="font-mono text-[11px] text-red-400 font-bold">Risk Score: 90 (Level 3)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      <strong>Bản chất:</strong> Dò quét mật khẩu theo từ điển hoặc vét cạn làm phát sinh liên tiếp các sự kiện đăng nhập thất bại.
                    </p>
                    <div className="text-[11px] text-emerald-400 mt-1 font-mono">
                      → Cơ chế bắt: Thống kê chuỗi sự kiện <code className="text-sky-300">ACTION_NAME = 'LOGON'</code> có <code className="text-sky-300">RETURN_CODE = 1017</code> (&gt;= 3 lần trong 15 phút).
                    </div>
                  </div>

                  <div className="bg-[#0b1322] border border-red-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">5. Truy cập khóa mã hóa trái phép (Trực tiếp &amp; Gián tiếp)</h4>
                      <span className="font-mono text-[11px] text-red-400 font-bold">Risk Score: 92 (Level 3)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      <strong>Bản chất:</strong>
                      <br />• <em>Truy cập trực tiếp:</em> Đọc trộm trực tiếp từ kho khóa/bảng hệ thống (<code className="text-sky-300 font-mono">V$ENCRYPTION_KEYS</code>, <code className="text-sky-300 font-mono">V$ENCRYPTION_WALLET</code>, <code className="text-sky-300 font-mono">SYS.ENC$</code>, bảng lưu Master Key).
                      <br />• <em>Truy cập gián tiếp:</em> Lợi dụng ứng dụng, dịch vụ hoặc package có quyền sử dụng khóa (<code className="text-sky-300 font-mono">DBMS_CRYPTO.DECRYPT</code>, <code className="text-sky-300 font-mono">ADMINISTER KEY MANAGEMENT</code>) để giải mã dữ liệu nhạy cảm mà không cần nhìn thấy khóa gốc.
                    </p>
                    <div className="text-[11px] text-emerald-400 mt-1 font-mono">
                      → Cơ chế bắt: Giám sát từ khóa đối tượng mật mã &amp; hàm <code className="text-sky-300">DBMS_CRYPTO</code> trong Audit Trail.
                    </div>
                  </div>
                </div>
              </div>

              {/* Group B: Inference Attacks on Statistical Databases (SDB) */}
              <div className="space-y-3 pt-3 border-t border-white/10">
                <h3 className="font-bold text-amber-300 text-[14px] flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 font-mono text-[11px]">PHÂN NHÓM II</span>
                  <span>Các Kiểu Tấn công Suy diễn (Inference Attacks) vào CSDL Thống kê (SDB - 4 Kiểu)</span>
                </h3>

                <div className="grid grid-cols-1 gap-3">
                  <div className="bg-[#0b1322] border border-red-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">1. Tấn công trực tiếp (Direct Attack)</h4>
                      <span className="font-mono text-[11px] text-red-400 font-bold">Risk Score: 95 (Level 3)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      Dùng truy vấn thông thường hoặc điều kiện lọc đặc thù để truy xuất thẳng dữ liệu cá nhân nhạy cảm (ví dụ lọc theo mã nhân viên hoặc chạm vào bản ghi bẫy <code className="text-red-300 font-mono">MANV = 'NV_TRAP'</code>).
                    </p>
                  </div>

                  <div className="bg-[#0b1322] border border-amber-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">2. Tấn công dựa vào đếm (Count-based Attack)</h4>
                      <span className="font-mono text-[11px] text-amber-400 font-bold">Risk Score: 65 (Level 2)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      Kết hợp kết quả đếm (<code className="text-sky-300 font-mono">COUNT = 1</code>) và tính tổng (<code className="text-sky-300 font-mono">SUM</code>) trên cùng một mệnh đề điều kiện <code className="text-sky-300 font-mono">WHERE</code>. Khi <code className="text-sky-300 font-mono">COUNT(*) = 1</code>, giá trị <code className="text-sky-300 font-mono">SUM(LUONG)</code> chính là mức lương của cá nhân duy nhất thỏa mãn điều kiện đó.
                    </p>
                  </div>

                  <div className="bg-[#0b1322] border border-amber-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">3. Tấn công trình theo dõi (Tracker Attack)</h4>
                      <span className="font-mono text-[11px] text-amber-400 font-bold">Risk Score: 70 (Level 2)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      Lách qua cơ chế kiểm soát kích cỡ tập truy vấn (Query-Set-Size Control — khi hệ thống từ chối trả lời các truy vấn có <code className="text-sky-300 font-mono">COUNT &lt; k</code>) bằng cách độn thêm điều kiện phụ (Tracker <code className="text-sky-300 font-mono">T</code>) để chia thành các tập truy vấn lớn hợp lệ rồi trừ cho nhau.
                    </p>
                  </div>

                  <div className="bg-[#0b1322] border border-amber-500/20 rounded-lg p-3.5">
                    <div className="flex items-center justify-between">
                      <h4 className="font-bold text-slate-100 text-[13px]">4. Tấn công hệ tuyến tính (Linear System Attack)</h4>
                      <span className="font-mono text-[11px] text-amber-400 font-bold">Risk Score: 72 (Level 2)</span>
                    </div>
                    <p className="text-[12px] text-slate-400 mt-1">
                      Thiết lập và giải hệ phương trình đại số tuyến tính <code className="text-sky-300 font-mono">A · X = B</code> từ nhiều truy vấn thống kê <code className="text-sky-300 font-mono">SUM</code> trên các tập con chồng lấp để tìm ra toàn bộ dữ liệu lương cá nhân của tất cả nhân viên.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 2: Mathematical Model of SDB Inference Attacks */}
        {activeSection === 'sdb_math' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-5">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Calculator className="w-5 h-5 text-amber-400" />
              <h2 className="text-[16px] font-bold text-slate-100">
                2. Mô hình Toán học &amp; Ví dụ Thực nghiệm 4 Kiểu Tấn công Suy diễn SDB trên Bảng SYS.NV
              </h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-4 leading-relaxed">
              <p>
                Giả sử CSDL Thống kê (SDB) chỉ cho phép người dùng thực hiện các hàm tổng hợp (<code className="font-mono text-sky-300">COUNT, SUM, AVG</code>) trên bảng <code className="font-mono text-sky-300">SYS.NV</code> gồm 4 nhân viên nghiệp vụ: <code className="font-mono">NV1 (900), NV2 (850), NV3 (1200), NV4 (950)</code>. Dưới đây là cơ chế toán học của từng kiểu tấn công suy diễn và cách IDS phát hiện:
              </p>

              {/* 1. Direct Attack */}
              <div className="bg-[#0b1322] border border-white/10 rounded-xl p-4 space-y-2">
                <div className="font-bold text-red-300 text-[13.5px]">2.1. Tấn công trực tiếp (Direct Attack)</div>
                <p className="text-[12px] text-slate-300">
                  Kẻ tấn công truy vấn thẳng vào bản ghi mục tiêu hoặc lọc điều kiện chỉ chứa 1 người mà không bị hạn chế kích thước tập kết quả:
                </p>
                <pre className="bg-[#070d18] p-3 rounded-lg font-mono text-[11.5px] text-sky-300 overflow-x-auto">
{`SELECT HOTEN, LUONG, CMND FROM SYS.NV WHERE MANV = 'NV3';
-- Hoặc quét trúng bản ghi bẫy Honeytoken:
SELECT * FROM SYS.NV WHERE MANV = 'NV_TRAP';`}
                </pre>
              </div>

              {/* 2. Count-based Attack */}
              <div className="bg-[#0b1322] border border-white/10 rounded-xl p-4 space-y-2">
                <div className="font-bold text-amber-300 text-[13.5px]">2.2. Tấn công dựa vào đếm (Count-based Attack: COUNT = 1 &amp; SUM)</div>
                <p className="text-[12px] text-slate-300">
                  Kẻ tấn công biết Lê Văn C là <code className="font-mono">Nam</code> và có số CMND chứa đuôi <code className="font-mono">8888</code>. Hắn thực hiện phép thử kết hợp <code className="font-mono text-sky-300">COUNT</code> và <code className="font-mono text-sky-300">SUM</code>:
                </p>
                <pre className="bg-[#070d18] p-3 rounded-lg font-mono text-[11.5px] text-sky-300 overflow-x-auto">
{`SELECT COUNT(*), SUM(LUONG) 
FROM SYS.NV 
WHERE GIOITINH = 'Nam' AND CMND LIKE '%8888%';
-- Kết quả trả về: COUNT(*) = 1  |  SUM(LUONG) = 1200
-- => Suy diễn chính xác: Lương của Lê Văn C = 1200!`}
                </pre>
              </div>

              {/* 3. Tracker Attack */}
              <div className="bg-[#0b1322] border border-white/10 rounded-xl p-4 space-y-2">
                <div className="font-bold text-amber-300 text-[13.5px]">2.3. Tấn công trình theo dõi (Tracker Attack - Lách ngưỡng kích thước k &gt;= 2)</div>
                <p className="text-[12px] text-slate-300">
                  Khi hệ thống SDB áp dụng quy tắc chỉ trả lời truy vấn nếu số bản ghi thỏa mãn <code className="font-mono text-emerald-300">2 &lt;= COUNT(C) &lt;= N - 2</code>, truy vấn trực tiếp vào 1 cá nhân <code className="font-mono">C = (MANV='NV3')</code> sẽ bị chặn vì <code className="font-mono">COUNT = 1</code>. Kẻ tấn công chọn công thức trình theo dõi <code className="font-mono text-amber-300">T = (GIOITINH = 'Nam')</code> và thực hiện 2 truy vấn hợp lệ (mỗi truy vấn đều có <code className="font-mono">COUNT &gt;= 2</code>):
                </p>
                <pre className="bg-[#070d18] p-3 rounded-lg font-mono text-[11.5px] text-sky-300 overflow-x-auto">
{`-- Truy vấn 1 (Hợp của C và T): Gồm NV1 và NV3 (COUNT = 2 >= 2 -> Hợp lệ!)
SELECT SUM(LUONG) FROM SYS.NV WHERE (MANV = 'NV3' OR GIOITINH = 'Nam');  --> Kết quả Q1 = 2100

-- Truy vấn 2 (Phần bù của C giao với T): Gồm NV1 và NV4 để đủ ngưỡng k>=2
SELECT SUM(LUONG) FROM SYS.NV WHERE (MANV != 'NV3' AND GIOITINH = 'Nam'); --> Kết quả Q2 = 900

-- Công thức suy diễn Tracker: Lương(NV3) = Q1 - Q2 = 2100 - 900 = 1200!`}
                </pre>
              </div>

              {/* 4. Linear System Attack */}
              <div className="bg-[#0b1322] border border-white/10 rounded-xl p-4 space-y-2">
                <div className="font-bold text-amber-300 text-[13.5px]">2.4. Tấn công hệ tuyến tính (Linear System Attack: Giải hệ A · X = B)</div>
                <p className="text-[12px] text-slate-300">
                  Để tìm toàn bộ lương <code className="font-mono">(x1, x2, x3, x4)</code> của cả 4 nhân viên mà mỗi truy vấn đều chứa từ 3 người trở lên (hợp lệ hoàn toàn với bộ lọc kích thước tập kết quả), kẻ tấn công phát đi 4 câu lệnh <code className="font-mono text-sky-300">SUM(LUONG)</code> tạo thành hệ 4 phương trình tuyến tính độc lập:
                </p>
                <pre className="bg-[#070d18] p-3 rounded-lg font-mono text-[11.5px] text-sky-300 overflow-x-auto">
{`q1: SELECT SUM(LUONG) FROM SYS.NV WHERE MANV IN ('NV1','NV2','NV3'); --> x1 + x2 + x3      = 2950
q2: SELECT SUM(LUONG) FROM SYS.NV WHERE MANV IN ('NV1','NV2','NV4'); --> x1 + x2      + x4 = 2700
q3: SELECT SUM(LUONG) FROM SYS.NV WHERE MANV IN ('NV1','NV3','NV4'); --> x1      + x3 + x4 = 3050
q4: SELECT SUM(LUONG) FROM SYS.NV WHERE MANV IN ('NV2','NV3','NV4'); -->      x2 + x3 + x4 = 3000

-- Cộng 4 phương trình: 3*(x1 + x2 + x3 + x4) = 11700 => Tổng S = 3900
-- Giải ra toàn bộ CSDL:
-- x4 = S - 2950 = 950  (Phạm Thị D)
-- x3 = S - 2700 = 1200 (Lê Văn C)
-- x2 = S - 3050 = 850  (Trần Thị B)
-- x1 = S - 3000 = 900  (Nguyễn Văn A)`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Section 3: Architecture */}
        {activeSection === 'architecture' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Layers className="w-5 h-5 text-sky-400" />
              <h2 className="text-[16px] font-bold text-slate-100">3. Kiến trúc Phòng thủ Chiều sâu (Defense-in-Depth)</h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-3 leading-relaxed">
              <p>
                Mô hình Defense-in-Depth của hệ thống được tổ chức thành 5 tầng bảo vệ khép kín:
              </p>

              <div className="space-y-3 pt-1">
                <div className="bg-[#0b1322] border border-amber-500/25 rounded-lg p-3.5 flex items-start gap-3">
                  <span className="w-7 h-7 rounded-lg bg-amber-500/20 text-amber-300 flex items-center justify-center font-bold text-[12px] shrink-0 font-mono">
                    Tầng 1
                  </span>
                  <div>
                    <h4 className="font-bold text-slate-100 text-[13px]">Internal Database Interception (Autonomous Trigger)</h4>
                    <p className="text-[11.5px] text-slate-400 mt-1">
                      Trigger <code className="text-amber-300 font-mono">SYS.TRG_PROTECT_NV</code> hoạt động ngay bên trong nhân Oracle DBMS, bắt chặn các thao tác gian lận lương &gt; 50% và xóa nhân viên trước khi dữ liệu bị biến đổi vật lý trên đĩa.
                    </p>
                  </div>
                </div>

                <div className="bg-[#0b1322] border border-purple-500/25 rounded-lg p-3.5 flex items-start gap-3">
                  <span className="w-7 h-7 rounded-lg bg-purple-500/20 text-purple-300 flex items-center justify-center font-bold text-[12px] shrink-0 font-mono">
                    Tầng 2
                  </span>
                  <div>
                    <h4 className="font-bold text-slate-100 text-[13px]">Fine-Grained Auditing &amp; Bẫy Honeytoken (DBMS_FGA)</h4>
                    <p className="text-[11.5px] text-slate-400 mt-1">
                      Gài bản ghi bẫy <code className="text-red-400 font-mono font-bold">MANV = 'NV_TRAP'</code> và chính sách giám sát cột nhạy cảm <code className="text-purple-300 font-mono">LUONG &gt;= 1000</code>. Chặn đứng các hành vi đọc trộm dữ liệu mà Trigger không thể can thiệp được.
                    </p>
                  </div>
                </div>

                <div className="bg-[#0b1322] border border-sky-500/25 rounded-lg p-3.5 flex items-start gap-3">
                  <span className="w-7 h-7 rounded-lg bg-sky-500/20 text-sky-300 flex items-center justify-center font-bold text-[12px] shrink-0 font-mono">
                    Tầng 3
                  </span>
                  <div>
                    <h4 className="font-bold text-slate-100 text-[13px]">Unified Audit Trail &amp; Telemetry</h4>
                    <p className="text-[11.5px] text-slate-400 mt-1">
                      Khai thác toàn bộ thông tin ngữ cảnh: <code className="text-sky-300 font-mono">OS_USERNAME</code>, <code className="text-sky-300 font-mono">USERHOST</code>, <code className="text-sky-300 font-mono">CLIENT_PROGRAM_NAME</code> và <code className="text-sky-300 font-mono">RETURN_CODE</code> từ kho kiểm toán hợp nhất UNIFIED_AUDIT_TRAIL.
                    </p>
                  </div>
                </div>

                <div className="bg-[#0b1322] border border-cyan-500/25 rounded-lg p-3.5 flex items-start gap-3">
                  <span className="w-7 h-7 rounded-lg bg-cyan-500/20 text-cyan-300 flex items-center justify-center font-bold text-[12px] shrink-0 font-mono">
                    Tầng 4
                  </span>
                  <div>
                    <h4 className="font-bold text-slate-100 text-[13px]">Multi-Dimensional IDS Detection Engine</h4>
                    <p className="text-[11.5px] text-slate-400 mt-1">
                      Phân tích toàn bộ 5 dạng tấn công kỹ thuật DBMS (SQLi, Masquerading, Privilege Escalation, Brute-force, Crypto Key Access) và 4 kiểu tấn công suy diễn SDB (Direct, Count-based, Tracker, Linear System).
                    </p>
                  </div>
                </div>

                <div className="bg-[#0b1322] border border-red-500/25 rounded-lg p-3.5 flex items-start gap-3">
                  <span className="w-7 h-7 rounded-lg bg-red-500/20 text-red-300 flex items-center justify-center font-bold text-[12px] shrink-0 font-mono">
                    Tầng 5
                  </span>
                  <div>
                    <h4 className="font-bold text-slate-100 text-[13px]">Graduated Active Response &amp; Isolation (IPS)</h4>
                    <p className="text-[11.5px] text-slate-400 mt-1">
                      Hệ thống tự động kích hoạt phản ứng dựa trên Risk Score: Phân cấp từ Cảnh báo (Level 1) đến Thu hồi quyền DML (Level 2: Read-Only) và Cách ly hoàn toàn (Level 3: Lock + Kill Session).
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 4: Trigger */}
        {activeSection === 'trigger' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Zap className="w-5 h-5 text-amber-400" />
              <h2 className="text-[16px] font-bold text-slate-100">4. Cơ chế Trigger Tự trị (Autonomous Transaction Trigger)</h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-3 leading-relaxed">
              <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-200 text-[12px]">
                <strong>Vấn đề kinh điển trong Database Security:</strong> Khi một Database Trigger ném ngoại lệ <code className="font-mono">RAISE_APPLICATION_ERROR</code> để hủy thao tác gian lận của người dùng, toàn bộ các câu lệnh DML bên trong Trigger đó cũng sẽ bị Oracle ROLLBACK theo mặc định! Điều này khiến kẻ tấn công không để lại dấu vết trong bảng nhật ký.
              </div>

              <h3 className="font-bold text-slate-100 text-[14px] pt-1">Giải pháp Kỹ thuật: PRAGMA AUTONOMOUS_TRANSACTION</h3>
              <p>
                Đề tài sử dụng chỉ thị <code className="text-amber-300 font-mono font-bold">PRAGMA AUTONOMOUS_TRANSACTION</code>. Chỉ thị này tạo ra một phân vùng giao dịch độc lập hoàn toàn với phiên chính của người dùng:
              </p>
              <ol className="list-decimal pl-5 space-y-1.5 text-slate-300 text-[12.5px]">
                <li>Khi phát hiện vi phạm, Trigger ghi nhận chi tiết vào bảng <code className="text-sky-300 font-mono">SYS.IDS_TRIGGER_ALERTS</code>.</li>
                <li>Thực thi lệnh <code className="text-emerald-300 font-mono font-bold">COMMIT;</code> ngay trong giao dịch tự trị. Dòng cảnh báo được ghi vĩnh viễn vào CSDL.</li>
                <li>Sau đó mới gọi <code className="text-red-400 font-mono font-bold">RAISE_APPLICATION_ERROR(-20001 / -20002)</code> để chặn đứng người dùng. Giao dịch chính bị Rollback nhưng log cảnh báo vẫn an toàn 100%.</li>
              </ol>

              <div className="relative pt-2">
                <div className="flex items-center justify-between bg-[#080d17] px-3.5 py-2 rounded-t-lg border-x border-t border-white/10">
                  <span className="text-[11px] font-mono font-bold text-slate-400">PL/SQL Autonomous Trigger</span>
                  <button
                    onClick={() => handleCopy('trigger_code', `CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV\nBEFORE UPDATE OR DELETE ON SYSTEM.NV\nFOR EACH ROW\nDECLARE\n    PRAGMA AUTONOMOUS_TRANSACTION;\n    v_user VARCHAR2(50);\nBEGIN\n    v_user := SYS_CONTEXT('USERENV', 'SESSION_USER');\n    IF DELETING THEN\n        INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)\n        VALUES (v_user, 'UNAUTHORIZED_DELETE', 'Cố tình xóa nhân viên mã: ' || :OLD.manv);\n        COMMIT;\n        RAISE_APPLICATION_ERROR(-20001, 'IDS BLOCK: Ban khong duoc phep xoa du lieu nhan vien!');\n    END IF;\n    IF UPDATING('LUONG') AND :NEW.luong > :OLD.luong * 1.5 THEN\n        INSERT INTO SYS.IDS_TRIGGER_ALERTS (db_user, attack_type, details)\n        VALUES (v_user, 'ABNORMAL_SALARY_MODIFICATION', 'Tăng lương bất thường từ ' || :OLD.luong || ' lên ' || :NEW.luong);\n        COMMIT;\n        RAISE_APPLICATION_ERROR(-20002, 'IDS BLOCK: Phat hien hanh vi gian lan tang luong vuot nguong!');\n    END IF;\nEND;`)}
                    className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-white cursor-pointer"
                  >
                    {copiedSnippet === 'trigger_code' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedSnippet === 'trigger_code' ? 'Đã sao chép' : 'Sao chép'}</span>
                  </button>
                </div>
                <pre className="bg-[#070d18] p-4 rounded-b-lg border border-white/10 font-mono text-[11px] text-sky-300 overflow-x-auto leading-relaxed">
{`CREATE OR REPLACE TRIGGER SYS.TRG_PROTECT_NV
BEFORE UPDATE OR DELETE ON SYSTEM.NV
FOR EACH ROW
DECLARE
    PRAGMA AUTONOMOUS_TRANSACTION;
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
END;`}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Section 5: Honeytoken & FGA */}
        {activeSection === 'honeytoken' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Target className="w-5 h-5 text-purple-400" />
              <h2 className="text-[16px] font-bold text-slate-100">5. Bẫy Dữ liệu Honeytoken Canary &amp; Fine-Grained Auditing (DBMS_FGA)</h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-3 leading-relaxed">
              <h3 className="font-bold text-slate-100 text-[14px]">Tại sao cần bẫy Honeytoken trong An toàn CSDL?</h3>
              <p>
                Trigger chỉ có thể bắt được các thao tác ghi dữ liệu (<code className="font-mono">UPDATE, DELETE</code>) mà <strong>hoàn toàn bất lực trước hành vi đọc trộm dữ liệu (SELECT)</strong> vì Oracle không cho phép viết Trigger <code className="font-mono">BEFORE SELECT</code> trên bảng thông thường.
              </p>
              <p>
                Để phát hiện kẻ tấn công trích xuất dữ liệu trái phép mà không làm chậm hệ thống, đề tài áp dụng cơ chế <strong>Honeytoken Canary Trap</strong>:
              </p>

              <div className="bg-[#0b1322] border border-purple-500/30 rounded-lg p-3.5 space-y-2">
                <div className="font-bold text-purple-300 text-[12.5px]">Đặc điểm của Bản ghi Bẫy Honeytoken (NV_TRAP):</div>
                <div className="font-mono text-[11.5px] text-slate-200">
                  MANV = 'NV_TRAP' | HOTEN = 'Hoàng Văn Sếp (VIP)' | LUONG = 99999 | CMND = '001099000000'
                </div>
                <p className="text-[11.5px] text-slate-400">
                  Bản ghi này không phục vụ cho bất kỳ quy trình nghiệp vụ thông thường nào. Một người dùng bình thường làm việc theo nhiệm vụ sẽ không bao giờ truy vấn đích danh mã nhân viên này. Do đó, bất kỳ truy vấn nào chạm vào <code className="text-red-300 font-mono">NV_TRAP</code> đều mang tính chất xâm nhập với <strong>độ tin cậy 100% (Zero False Positive)</strong>.
                </p>
              </div>

              <h3 className="font-bold text-slate-100 text-[14px] pt-1">Cấu hình DBMS_FGA:</h3>
              <pre className="bg-[#070d18] p-3.5 rounded-lg border border-white/10 font-mono text-[11px] text-purple-300 overflow-x-auto leading-relaxed">
{`-- 1. Bẫy Honeytoken (Toàn bộ thao tác chạm vào MANV = 'NV_TRAP')
BEGIN
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

-- 2. Giám sát cột nhạy cảm lương cao
BEGIN
    DBMS_FGA.ADD_POLICY(
        object_schema   => 'SYSTEM',
        object_name     => 'NV',
        policy_name     => 'FGA_HIGH_SALARY_ACCESS',
        audit_condition => 'luong >= 1000',
        audit_column    => 'LUONG, CMND',
        statement_types => 'SELECT, UPDATE, DELETE',
        enable          => TRUE
    );
END;`}
              </pre>
            </div>
          </div>
        )}

        {/* Section 6: Detection Engine */}
        {activeSection === 'detection' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Cpu className="w-5 h-5 text-cyan-400" />
              <h2 className="text-[16px] font-bold text-slate-100">6. Động cơ Nhận diện &amp; Thuật toán Chấm điểm Rủi ro (Risk Scoring)</h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-3 leading-relaxed">
              <p>
                Bộ não của IDS là <strong>Detection Engine</strong> phân tích dữ liệu hợp nhất từ Audit Trail và Trigger theo các quy tắc chuyên biệt:
              </p>

              <div className="space-y-2.5 pt-1">
                <div className="bg-[#0b1322] border border-white/5 p-3 rounded-lg">
                  <div className="font-bold text-red-300 text-[12.5px]">1. Nhận diện 5 Dạng Tấn công Kỹ thuật DBMS:</div>
                  <ul className="list-disc pl-5 text-[11.5px] text-slate-300 mt-1 space-y-1">
                    <li><strong>SQL Injection (Score 95):</strong> Khớp mẫu chữ ký <code className="font-mono text-sky-300">OR 1=1, UNION SELECT, --, /*, DBMS_PIPE, UTL_HTTP</code>.</li>
                    <li><strong>Masquerading Attack (Score 75):</strong> Phát hiện đăng nhập hợp lệ nhưng sai lệch hồ sơ <code className="font-mono text-sky-300">OS_USERNAME, USERHOST, CLIENT_PROGRAM_NAME</code>.</li>
                    <li><strong>Privilege Escalation (Score 88):</strong> Phát hiện thực thi <code className="font-mono text-sky-300">GRANT, REVOKE, CREATE/ALTER/DROP USER</code> trái phép.</li>
                    <li><strong>Failed Logins / Brute-Force (Score 90):</strong> Đếm số lần <code className="font-mono text-sky-300">ORA-01017 &gt;= 3</code> trong cửa sổ 15 phút.</li>
                    <li><strong>Unauthorized Encryption Key Access (Score 92):</strong> Giám sát truy cập trực tiếp bảng khóa (<code className="font-mono text-sky-300">V$ENCRYPTION_KEYS, ENC$</code>) và gián tiếp qua <code className="font-mono text-sky-300">DBMS_CRYPTO.DECRYPT</code>.</li>
                  </ul>
                </div>

                <div className="bg-[#0b1322] border border-white/5 p-3 rounded-lg">
                  <div className="font-bold text-amber-300 text-[12.5px]">2. Nhận diện 4 Kiểu Tấn công Suy diễn CSDL Thống kê (SDB):</div>
                  <ul className="list-disc pl-5 text-[11.5px] text-slate-300 mt-1 space-y-1">
                    <li><strong>Direct Attack (Score 95):</strong> Chạm trực tiếp bẫy <code className="font-mono text-red-300">FGA_HONEYTOKEN_TRAP</code> hoặc truy xuất trực tiếp cá nhân.</li>
                    <li><strong>Count-based Attack (Score 65):</strong> Truy vấn kết hợp <code className="font-mono text-sky-300">COUNT(*)</code> và <code className="font-mono text-sky-300">SUM/AVG</code> trên điều kiện lọc hẹp để cô lập <code className="font-mono">COUNT = 1</code>.</li>
                    <li><strong>Tracker Attack (Score 70):</strong> Chuỗi truy vấn thống kê sử dụng mệnh đề phần bù <code className="font-mono text-sky-300">(C OR T)</code> và <code className="font-mono text-sky-300">(NOT C AND T)</code> để lách kiểm soát kích thước tập kết quả.</li>
                    <li><strong>Linear System Attack (Score 72):</strong> Chuỗi <code className="font-mono text-sky-300">&gt;= 3 truy vấn SUM/AVG</code> trên các tập con <code className="font-mono text-sky-300">IN (...)</code> khác nhau nhằm lập hệ phương trình tuyến tính <code className="font-mono">A · X = B</code>.</li>
                  </ul>
                </div>

                <div className="bg-[#0b1322] border border-white/5 p-3 rounded-lg">
                  <div className="font-bold text-purple-300 text-[12.5px]">3. Công thức Tổng hợp Điểm Rủi ro (Cumulative Risk Score):</div>
                  <div className="bg-[#070d18] p-2.5 rounded font-mono text-[11.5px] text-emerald-400 mt-1">
                    Total_Risk = min(100, max(Scores) + min(14, (Count - 1) * 4))
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 7: IPS */}
        {activeSection === 'ips' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <Lock className="w-5 h-5 text-emerald-400" />
              <h2 className="text-[16px] font-bold text-slate-100">7. Phản ứng Đa cấp Chủ động (Graduated Active Response &amp; IPS)</h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-3 leading-relaxed">
              <p>
                Khác biệt lớn nhất giữa một hệ thống IDS thuần túy và một hệ thống <strong>Active IPS</strong> là khả năng can thiệp tự động tức thì ngay khi vi phạm vượt ngưỡng rủi ro, không cần chờ đợi con người can thiệp thủ công:
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-1">
                <div className="bg-[#0b1322] border border-amber-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-amber-300 text-[13px]">Level 2: Privilege Containment</span>
                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                      Score: 50 – 79
                    </span>
                  </div>
                  <p className="text-[11.5px] text-slate-300 mb-2">
                    <strong>Hạ quyền DML (Chuyển sang chế độ Read-Only):</strong>
                  </p>
                  <div className="bg-[#070d18] p-2.5 rounded font-mono text-[11px] text-amber-200">
                    REVOKE INSERT, UPDATE, DELETE ON SYS.NV FROM [USER];<br />
                    GRANT SELECT ON SYS.NV TO [USER];
                  </div>
                  <p className="text-[11px] text-slate-400 mt-2">
                    Áp dụng cho: Giả mạo Masquerading, Tấn công suy diễn SDB (Count-based, Tracker, Linear System), Trigger chặn sửa lương.
                  </p>
                </div>

                <div className="bg-[#0b1322] border border-red-500/30 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-red-300 text-[13px]">Level 3: Full Isolation</span>
                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40">
                      Score: 80 – 100
                    </span>
                  </div>
                  <p className="text-[11.5px] text-slate-300 mb-2">
                    <strong>Khóa tài khoản và ngắt tức thời kết nối:</strong>
                  </p>
                  <div className="bg-[#070d18] p-2.5 rounded font-mono text-[11px] text-red-200">
                    ALTER USER [USER] ACCOUNT LOCK;<br />
                    ALTER SYSTEM KILL SESSION 'sid,serial#' IMMEDIATE;
                  </div>
                  <p className="text-[11px] text-slate-400 mt-2">
                    Áp dụng cho: SQL Injection, Leo thang đặc quyền, Brute-force Logon, Truy cập khóa mã hóa trái phép, Chạm bẫy Honeytoken (Direct Attack).
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 8: PL/SQL scripts */}
        {activeSection === 'plsql' && (
          <div className="bg-[#101b2e] border border-sky-500/20 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2.5 border-b border-white/5 pb-3">
              <FileCode className="w-5 h-5 text-sky-400" />
              <h2 className="text-[16px] font-bold text-slate-100">8. Kịch bản PL/SQL Triển khai trên Oracle 23ai</h2>
            </div>

            <div className="text-[13px] text-slate-300 space-y-3 leading-relaxed">
              <p>
                Toàn bộ các lệnh khởi tạo hạ tầng an toàn CSDL trên Oracle Database 23ai / 19c / 21c (PDB: FREEPDB1):
              </p>

              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between text-[11.5px] font-bold text-slate-300 mb-1.5">
                    <span>1. Khởi tạo Bảng SYS.NV, Bảng Log &amp; User Thực nghiệm</span>
                  </div>
                  <pre className="bg-[#070d18] p-3.5 rounded-lg border border-white/10 font-mono text-[11px] text-sky-300 overflow-x-auto leading-relaxed">
{`-- Tạo bảng nhân viên
CREATE TABLE SYSTEM.NV (
    manv VARCHAR2(20) PRIMARY KEY,
    hoten VARCHAR2(100),
    luong NUMBER(10, 2),
    gioitinh VARCHAR2(10),
    cmnd VARCHAR2(20)
);

-- Tạo bảng ghi nhận cảnh báo Trigger tự trị
CREATE TABLE SYS.IDS_TRIGGER_ALERTS (
    alert_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time TIMESTAMP DEFAULT SYSTIMESTAMP,
    db_user VARCHAR2(50),
    attack_type VARCHAR2(100),
    details VARCHAR2(500)
);

-- Khởi tạo User thực nghiệm U1..U4 (Mật khẩu được cấu hình bảo mật qua biến môi trường)
CREATE USER U1 IDENTIFIED BY "••••••••";
CREATE USER U2 IDENTIFIED BY "••••••••";
CREATE USER U3 IDENTIFIED BY "••••••••";
CREATE USER U4 IDENTIFIED BY "••••••••";
GRANT CREATE SESSION TO U1, U2, U3, U4;
GRANT SELECT, INSERT, UPDATE, DELETE ON SYSTEM.NV TO U1, U2, U3, U4;`}
                  </pre>
                </div>

                <div>
                  <div className="flex items-center justify-between text-[11.5px] font-bold text-slate-300 mb-1.5">
                    <span>2. Cấu hình Unified Audit Policies (Bao gồm cả Giám sát Khóa mã hóa &amp; Đặc quyền)</span>
                  </div>
                  <pre className="bg-[#070d18] p-3.5 rounded-lg border border-white/10 font-mono text-[11px] text-purple-300 overflow-x-auto leading-relaxed">
{`-- Policy giám sát thao tác DML trên bảng NV
CREATE AUDIT POLICY ids_dml_nv_pol ACTIONS SELECT, INSERT, UPDATE, DELETE ON SYSTEM.NV;
AUDIT POLICY ids_dml_nv_pol;

-- Policy giám sát leo thang đặc quyền
CREATE AUDIT POLICY ids_priv_abuse_pol ACTIONS GRANT, REVOKE, CREATE USER, ALTER USER, DROP USER;
AUDIT POLICY ids_priv_abuse_pol;

-- Policy giám sát truy cập khóa mã hóa (Trực tiếp & Gián tiếp)
CREATE AUDIT POLICY ids_crypto_key_pol
  ACTIONS ADMINISTER KEY MANAGEMENT,
          EXECUTE ON SYS.DBMS_CRYPTO,
          SELECT ON SYS.V_$ENCRYPTION_KEYS,
          SELECT ON SYS.V_$ENCRYPTION_WALLET;
AUDIT POLICY ids_crypto_key_pol;`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
