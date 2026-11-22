@echo off
title Khoi dong toan bo he thong Oracle DB-IDS
echo ====================================================================
echo   HE THONG AN TOAN CSDL ^& PHAT HIEN XAM NHAP ORACLE 23ai (DB-IDS/IPS)
echo ====================================================================
echo.
echo [1/2] Dang khoi dong Web Dashboard (Port 3000)...
start "Web Dashboard (React + Express)" cmd /k "cd /d ""%~dp0dashboardweb"" && set BRIDGE_MANAGED_EXTERNALLY=1 && npm run dev"

timeout /t 3 > nul

echo [2/2] Dang khoi dong Oracle Live Sync Bridge...
start "Oracle Live Sync Bridge" cmd /k "cd /d ""%~dp0oracle"" && set NO_BROWSER=1 && python bridge.py"

echo.
echo ====================================================================
echo HE THONG DA KHOI DONG THANH CONG!
echo 0. Cau hinh moi truong    : Copy .env.example thanh .env tai thu muc goc
echo                             va dien ORACLE_PASSWORD, SOC_ADMIN_TOKEN
echo                             (neu bo trong SOC_ADMIN_TOKEN, xem token tam
echo                              duoc in tren console Web Dashboard).
echo 1. Giao dien Web Dashboard : http://localhost:3000
echo 2. Oracle SQL Developer    : Chay cac lenh trong file oracle\DEMO_COMMANDS.sql
echo ====================================================================
pause
