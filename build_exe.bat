@echo off
REM ===========================================================================
REM  build_exe.bat - mengubah antivirus.py menjadi satu file ScanGuard.exe
REM  Jalankan dengan klik dua kali, atau dari Command Prompt: build_exe.bat
REM ===========================================================================
setlocal
cd /d "%~dp0"

echo [1/5] Memeriksa Python...
where python >nul 2>nul
if errorlevel 1 (
    echo    GAGAL: Python tidak ditemukan di PATH.
    echo    Pasang Python dari https://www.python.org/downloads/ lalu centang
    echo    "Add python.exe to PATH" saat memasang.
    pause
    exit /b 1
)
python --version

echo.
echo [2/5] Memasang kebutuhan build ^(PyInstaller, yara-python, pefile^)...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo    GAGAL memasang kebutuhan build.
    pause
    exit /b 1
)

echo.
echo [3/5] Memeriksa mesin deteksi...
python -c "import yara; print('   yara-python OK', yara.__version__)"
python -c "import pefile; print('   pefile OK', pefile.__version__)"
where clamscan >nul 2>nul && (echo    ClamAV terdeteksi.) || (echo    ClamAV tidak ada - mesin ini akan dilewati, tidak masalah.)

echo.
echo [4/5] Membuat ikon aplikasi...
python tools\make_icon.py

echo.
echo [5/5] Mengompilasi menjadi .exe...
python -m PyInstaller --noconfirm --clean ScanGuard.spec
if errorlevel 1 (
    echo    GAGAL: PyInstaller berhenti dengan error.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  SELESAI. Hasil ada di folder:  dist\ScanGuard.exe
echo  Ukuran kira-kira 25-40 MB karena ikut membawa mesin YARA.
echo  Berkas itu sudah bisa dijalankan di komputer lain tanpa
echo  memasang Python.
echo ============================================================
pause
