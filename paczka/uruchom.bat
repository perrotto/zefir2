@echo off
title Potwierdzenia akcyzy ZEFIR2
cd /d "%~dp0"
set "ZEFIR_DATA=%~dp0dane"
echo Potwierdzenia akcyzy ZEFIR2 dziala pod adresem http://127.0.0.1:5010
echo Nie zamykaj tego okna podczas pracy. Zamkniecie okna = wylaczenie aplikacji.
echo.
"%~dp0python\python.exe" "%~dp0app\app.py"
pause
