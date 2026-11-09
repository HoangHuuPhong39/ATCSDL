@echo off
title Khoi dong toan bo he thong Oracle DB-IDS
echo ====================================================================
echo   HE THONG AN TOAN CSDL ^& PHAT HIEN XAM NHAP ORACLE 23ai (DB-IDS/IPS)
echo ====================================================================
echo.
echo [1/2] Dang khoi dong Web Dashboard (Port 3000)...
start "Web Dashboard (React + Express)" cmd /k "cd /d ""%~dp0dashboardweb"" && npm run dev"

timeout /t 3 > nul

echo [2/2] Dang khoi dong Oracle Live Sync Bridge...
start "Oracle Live Sync Bridge" cmd /k "cd /d ""%~dp0oracle"" && set NO_BROWSER=1 && python bridge.py"

echo.
echo ====================================================================
echo HE THONG DA KHOI DONG THANH CONG!
echo 1. Giao dien Web Dashboard : http://localhost:3000
echo 2. Oracle SQL Developer    : Chay cac lenh trong file DEMO_COMMANDS.sql
echo ====================================================================
pause
