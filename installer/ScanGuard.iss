; ============================================================================
;  ScanGuard.iss - skrip installer untuk Inno Setup 6.3 atau lebih baru
;
;  Cara pakai:
;    1. Jalankan build_exe.bat dulu sampai muncul dist\ScanGuard.exe
;    2. Buka file ini dengan Inno Setup Compiler, lalu tekan F9 (Compile)
;    3. Hasilnya: installer\Output\ScanGuard-Setup-2.0.0.exe
;
;  Atau dari Command Prompt:
;    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\ScanGuard.iss
;
;  Bagian yang biasanya perlu Anda ubah saat memakai skrip ini untuk program
;  lain: AppName, AppVersion, AppPublisher, dan AppId (buat GUID baru).
; ============================================================================

; Periksa versi Inno Setup lebih dulu supaya pesan errornya jelas.
#if VER < 6300
  #error Inno Setup 6.3 atau lebih baru diperlukan. Unduh dari https://jrsoftware.org/isdl.php
#endif

; Pastikan file .exe hasil PyInstaller sudah ada sebelum mulai.
#if !FileExists(AddBackslash(SourcePath) + "..\dist\ScanGuard.exe")
  #error File ..\dist\ScanGuard.exe belum ada. Jalankan build_exe.bat terlebih dahulu.
#endif

#define AppName        "ScanGuard"
#define AppVersion     "2.0.0"
#define AppPublisher   "Proyek Edukasi ScanGuard"
#define AppExeName     "ScanGuard.exe"

[Setup]
; AppId adalah "nomor identitas" aplikasi. Windows memakai nilai ini untuk
; mengenali versi lama saat Anda memasang versi baru, dan untuk data uninstall.
; Kalau skrip ini dipakai untuk program lain, buat GUID baru dari menu
; Tools > Generate GUID di Inno Setup. JANGAN memakai GUID ini di dua program
; berbeda - keduanya akan saling menimpa saat dipasang.
AppId={{2B81E968-7910-4644-B8EA-E17CAB45C295}

AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion=2.0.0.0
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

; Pemasangan tanpa hak administrator. Windows akan memasang program ke folder
; milik pengguna ({localappdata}\Programs), jadi tidak muncul layar UAC.
; Kalau Anda memang butuh memasang untuk semua pengguna, ubah baris ini
; menjadi PrivilegesRequired=admin dan hapus baris di bawahnya.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; 64-bit: pemisah 32/64 bit hanya memengaruhi lokasi file dan registry.
; x64compatible berarti: boleh dipasang di Windows 64-bit, dan boleh juga di
; Windows ARM64 (lewat emulasi) maupun Windows 32-bit.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes

; Tampilan wizard gaya modern dan warna instalasi.
WizardStyle=modern

; Berkas keluaran installer.
OutputDir=Output
OutputBaseFilename=ScanGuard-Setup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} {#AppVersion}

; Kompresi maksimum membuat installer lebih kecil. Proses kompilasi jadi
; sedikit lebih lama, tetapi itu hanya terjadi sekali.
Compression=lzma2/max
SolidCompression=yes

; Tutup aplikasi yang sedang berjalan sebelum memperbarui file.
CloseApplications=yes

[Languages]
; Bahasa Indonesia dipilih bila Windows memakai bahasa Indonesia; kalau tidak,
; installer memakai bahasa Inggris. Keduanya disediakan Inno Setup.
Name: "indonesian"; MessagesFile: "compiler:Languages\Indonesian.isl"
Name: "english";    MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; Hanya satu file: hasil PyInstaller. Python dan seluruh pustakanya sudah
; berada di dalamnya, jadi tidak perlu memasang apa pun lagi.
Source: "..\dist\ScanGuard.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Tawarkan membuka program setelah pemasangan selesai.
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; Pemeriksaan mesin deteksi: mencetak status ke jendela console. Berguna untuk
; memastikan mesin YARA dan analisis PE benar-benar ikut terbungkus di komputer
; pengguna. Dijalankan hanya bila pengguna mencentangnya.
Filename: "{cmd}"; Parameters: "/k ""{app}\{#AppExeName}"" --cek-mesin"; Description: "Periksa mesin deteksi (membuka jendela hitam sebentar)"; Flags: postinstall unchecked

[UninstallDelete]
; Hanya folder aplikasi yang dibersihkan. Yang TIDAK ikut terhapus, dan memang
; disengaja:
;   * %LOCALAPPDATA%\ScanGuard  - berisi basis data hash, karantina, dan
;     pengaturan. Karantina harus tetap ada kalau pengguna memasang ulang,
;     supaya berkas yang dikarantina tidak hilang begitu saja.
;   * laporan pemindaian yang disimpan pengguna di folder lain.
Type: filesandordirs; Name: "{app}"
