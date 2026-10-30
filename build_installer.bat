@echo off
REM ===========================================================================
REM  build_installer.bat - membungkus dist\ScanGuard.exe menjadi setup.exe
REM  Memerlukan Inno Setup 6.3+ yang sudah terpasang.
REM  Unduh gratis di: https://jrsoftware.org/isdl.php
REM ===========================================================================
setlocal
cd /d "%~dp0"

if not exist "dist\ScanGuard.exe" (
    echo GAGAL: dist\ScanGuard.exe belum ada.
    echo Jalankan build_exe.bat terlebih dahulu.
    pause
    exit /b 1
)

set "ISCC="
for %%P in (
    "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
    "%ProgramFiles%\Inno Setup 6\ISCC.exe"
    "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
) do if exist "%%~P" set "ISCC=%%~P"

if not defined ISCC (
    echo GAGAL: ISCC.exe ^(compiler Inno Setup^) tidak ditemukan.
    echo Pasang Inno Setup 6 dari https://jrsoftware.org/isdl.php
    echo lalu jalankan skrip ini lagi.
    pause
    exit /b 1
)

echo Memakai compiler: %ISCC%
"%ISCC%" "installer\ScanGuard.iss"
if errorlevel 1 (
    echo GAGAL: kompilasi installer berhenti dengan error.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  SELESAI. Installer ada di folder:
echo    installer\Output\ScanGuard-Setup-2.0.0.exe
echo  Kirim satu file itu ke pengguna - cukup klik dua kali untuk
echo  memasang ScanGuard di komputer Windows mereka.
echo ============================================================
pause
