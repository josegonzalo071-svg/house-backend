@echo off
title HOUSE - Cerrando sistema...

echo ===============================
echo  CERRANDO BACKEND (node.exe)
echo ===============================
taskkill /F /IM node.exe >nul 2>&1

echo ===============================
echo  CERRANDO FRONTEND (http-server)
echo ===============================
taskkill /F /IM http-server.exe >nul 2>&1
taskkill /F /IM http-server >nul 2>&1

echo ===============================
echo  PROCESOS FINALIZADOS
echo ===============================

timeout /t 1 >nul
exit
