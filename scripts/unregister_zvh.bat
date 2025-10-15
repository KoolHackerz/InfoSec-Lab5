@echo off
chcp 65001 > nul
echo ╔════════════════════════════════════════════════════════╗
echo ║   Removing .zvh file association with program          ║
echo ╚════════════════════════════════════════════════════════╝
echo.
echo This script will remove .zvh extension registration
echo.
echo WARNING: Administrator rights required!
echo.
pause

REM Проверка прав администратора
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo Error: Administrator rights required!
    echo.
    echo Run this script as administrator
    echo.
    pause
    exit /b 1
)

echo.
echo Removing .zvh registration from Windows registry...

REM Удаление ассоциации файлов
reg delete "HKEY_CLASSES_ROOT\.zvh" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo Removed .zvh association
) else (
    echo .zvh association not found
)

REM Удаление типа файла
reg delete "HKEY_CLASSES_ROOT\ZVHFile" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo Removed ZVHFile type
) else (
    echo ZVHFile type not found
)

echo.
echo ═══════════════════════════════════════════════════════
echo Removal completed!
echo ═══════════════════════════════════════════════════════
echo.
pause
