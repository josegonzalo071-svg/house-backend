@echo off
title HOUSE - Iniciando sistema...

REM ---- Ruta del proyecto ----
cd /d "C:\Users\optim\Desktop\house_project"

echo ===============================
echo  INICIANDO BACKEND (server.js)
echo ===============================

start "HOUSE - Backend" cmd /k "node server.js"

timeout /t 2 >nul

echo ===============================
echo  INICIANDO FRONTEND (http-server)
echo ===============================

start "HOUSE - Frontend" cmd /k "http-server ."

timeout /t 2 >nul

echo ===============================
echo  ABRIENDO NAVEGADOR
echo ===============================

start "" "http://127.0.0.1:8080"

echo ===============================
echo  HOUSE INICIADO CORRECTAMENTE
echo  Puedes cerrar esta ventana.
echo ===============================

exit
