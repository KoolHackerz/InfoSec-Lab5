@echo off
chcp 65001 > nul
echo ╔════════════════════════════════════════════════════════╗
echo ║   Registering .zvh file association with program       ║
echo ╚════════════════════════════════════════════════════════╝
echo.
echo This script will register .zvh extension, so that
echo double-clicking on a .zvh file automatically opens
echo decryption program with a key request.
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
    echo Run this script as administrator:
    echo   1. Right-click on the file
    echo   2. Select "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM Получение полного пути к исполняемому файлу (поднимаемся на уровень выше из bats/)
set "PROGRAM_PATH=%~dp0..\target\release\InfoSec-Lab-5.exe"

REM Преобразование в абсолютный путь
pushd "%~dp0.."
set "PROGRAM_PATH=%CD%\target\release\InfoSec-Lab-5.exe"
popd

REM Проверка существования программы
if not exist "%PROGRAM_PATH%" (
    echo.
    echo Error: Program not found!
    echo.
    echo First build the project in release mode:
    echo   cargo build --release
    echo.
    echo Expected path: %PROGRAM_PATH%
    echo.
    pause
    exit /b 1
)

echo.
echo Found program: %PROGRAM_PATH%
echo.
echo Registering .zvh extension in Windows registry...

REM Создание ассоциации для расширения .zvh
reg add "HKEY_CLASSES_ROOT\.zvh" /ve /d "ZVHFile" /f >nul 2>&1
if %errorLevel% neq 0 (
    echo Error creating .zvh association
    pause
    exit /b 1
)
echo Registered .zvh extension

REM Настройка типа файла
reg add "HKEY_CLASSES_ROOT\ZVHFile" /ve /d "ZVH Encrypted File" /f >nul 2>&1
echo File type configured

REM Установка иконки (используем стандартную иконку замка)
reg add "HKEY_CLASSES_ROOT\ZVHFile\DefaultIcon" /ve /d "%%SystemRoot%%\System32\shell32.dll,47" /f >nul 2>&1
echo Icon set

REM Создание команды открытия
reg add "HKEY_CLASSES_ROOT\ZVHFile\shell\open" /ve /d "Decrypt and open" /f >nul 2>&1
reg add "HKEY_CLASSES_ROOT\ZVHFile\shell\open\command" /ve /d "\"%PROGRAM_PATH%\" open \"%%1\"" /f >nul 2>&1
if %errorLevel% neq 0 (
    echo Error creating open command
    pause
    exit /b 1
)
echo Open command created

REM Добавление дополнительных команд в контекстное меню
reg add "HKEY_CLASSES_ROOT\ZVHFile\shell\decrypt" /ve /d "Decrypt to..." /f >nul 2>&1
reg add "HKEY_CLASSES_ROOT\ZVHFile\shell\decrypt\command" /ve /d "cmd.exe /k \"%PROGRAM_PATH%\" decrypt -i \"%%1\" -o \"%%~dpn1%%~x1\" -k" /f >nul 2>&1
echo Context menu command added

echo.
echo ═══════════════════════════════════════════════════════
echo Registration completed successfully!
echo ═══════════════════════════════════════════════════════
echo.
echo Now you can:
echo   • Double-click on a .zvh file to decrypt it
echo   • The program will automatically ask for a key
echo   • The file will be decrypted and opened
echo.
echo To apply changes, you may need to refresh
echo Windows Explorer (press F5).
echo.
pause
