/*
   Aturan YARA bawaan ScanGuard.
   Format ini adalah standar industri: YARA dipakai oleh VirusTotal, sandbox
   malware, dan tim tanggap insiden di seluruh dunia.

   Catatan penting: aturan di bawah ini adalah contoh yang sudah disederhanakan
   untuk tujuan belajar dan untuk mengenali perilaku khas. Aturan YARA yang
   dipakai produk antivirus komersial jauh lebih banyak, lebih spesifik, dan
   diperbarui setiap hari oleh tim analis.

   Cara membaca aturan:
     strings   = potongan teks atau pola byte yang dicari di dalam berkas
     condition = syarat yang harus terpenuhi agar aturan dianggap cocok
     meta      = keterangan, tidak memengaruhi pencocokan
*/

/* --------------------------------------------------------------------------
   Berkas uji standar industri. Isinya tidak berbahaya. Setiap antivirus asli
   mengenalinya, jadi ini cara paling cepat memastikan mesin YARA bekerja.
   -------------------------------------------------------------------------- */
rule EICAR_Test_File
{
    meta:
        description = "Berkas uji standar industri antivirus (tidak berbahaya)"
        severity = "MALWARE"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

/* --------------------------------------------------------------------------
   Perilaku khas ransomware: menghapus salinan bayangan dan mematikan pemulihan
   Windows. Ransomware melakukan ini supaya korban tidak bisa memulihkan data.
   -------------------------------------------------------------------------- */
rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Menghapus shadow copy atau mematikan pemulihan sistem"
        severity = "MALWARE"
    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "vssadmin.exe delete shadows" nocase
        $vss3 = "wmic shadowcopy delete" nocase
        $wb1  = "wbadmin delete catalog" nocase
        $bcd1 = "bcdedit /set recoveryenabled no" nocase
        $bcd2 = "bcdedit /set {default} recoveryenabled no" nocase
    condition:
        any of them
}

rule Ransomware_Note_Language
{
    meta:
        description = "Teks khas catatan tebusan"
        severity = "MALWARE"
    strings:
        $n1 = "your files have been encrypted" nocase
        $n2 = "all your files are encrypted" nocase
        $n3 = "to decrypt your files" nocase
        $n4 = "send bitcoin" nocase
        $n5 = "bitcoin address" nocase
        $n6 = "do not rename" nocase
    condition:
        2 of them
}

/* --------------------------------------------------------------------------
   Pencuri kredensial. Ini alat yang sudah dikenal namanya; keberadaannya di
   sebuah berkas adalah alasan kuat untuk curiga.
   -------------------------------------------------------------------------- */
rule Credential_Stealer_Tools
{
    meta:
        description = "Nama alat pencuri kredensial yang dikenal"
        severity = "MALWARE"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa::logonpasswords" nocase
        $m3 = "lsadump::sam" nocase
        $m4 = "lazagne" nocase
        $m5 = "procdump -ma lsass" nocase
        $m6 = "comsvcs.dll, minidump" nocase
    condition:
        any of them
}

/* --------------------------------------------------------------------------
   Pemanggilan PowerShell yang disembunyikan. Pola "-enc" (perintah terenkode)
   dengan jendela tersembunyi hampir selalu berarti penyamaran.
   -------------------------------------------------------------------------- */
rule Suspicious_PowerShell_Execution
{
    meta:
        description = "PowerShell dijalankan tersembunyi dengan perintah terenkode"
        severity = "MENCURIGAKAN"
    strings:
        $ps    = "powershell" nocase
        $enc   = "-enc " nocase
        $enc2  = "-encodedcommand" nocase
        $hidden = "-windowstyle hidden" nocase
        $bypass = "-executionpolicy bypass" nocase
        $nop    = "-noprofile" nocase
    condition:
        $ps and (($enc or $enc2) or 2 of ($hidden, $bypass, $nop))
}

rule Script_Download_And_Run
{
    meta:
        description = "Mengunduh lalu menjalankan kode dari internet"
        severity = "MENCURIGAKAN"
    strings:
        $d1 = "downloadstring" nocase
        $d2 = "downloadfile" nocase
        $d3 = "invoke-webrequest" nocase
        $d4 = "wget " nocase
        $d5 = "curl -o" nocase
        $x1 = "invoke-expression" nocase
        $x2 = "iex(" nocase
        $x3 = "start-process" nocase
    condition:
        ($d1 or $d2 or $d3) or (($d4 or $d5) and ($x1 or $x2 or $x3))
}

/* --------------------------------------------------------------------------
   Cara bertahan di komputer korban (persistence) lewat registry autostart.
   -------------------------------------------------------------------------- */
rule Persistence_Autorun_Registry
{
    meta:
        description = "Menambahkan diri ke autostart Windows"
        severity = "MENCURIGAKAN"
    strings:
        $r1 = "currentversion\\run" nocase
        $r2 = "currentversion\\runonce" nocase
        $r3 = "currentversion\\policies\\explorer\\run" nocase
        $r4 = "schtasks /create" nocase
        $r5 = "reg add" nocase
    condition:
        ($r1 or $r2 or $r3) and ($r4 or $r5)
}

/* --------------------------------------------------------------------------
   Skrip yang menyembunyikan isinya dengan pengodean base64 lalu menjalankannya.
   -------------------------------------------------------------------------- */
rule Obfuscated_Script_Execution
{
    meta:
        description = "Menjalankan kode hasil dekode yang disembunyikan"
        severity = "MENCURIGAKAN"
    strings:
        $b1 = "base64" nocase
        $b2 = "frombase64string" nocase
        $e1 = "eval(" nocase
        $e2 = "exec(" nocase
        $e3 = "compile(" nocase
    condition:
        ($b1 or $b2) and ($e1 or $e2 or $e3)
}

/* --------------------------------------------------------------------------
   Mematikan pertahanan komputer sebelum beraksi. Setiap barisnya adalah nama
   alat keamanan yang sengaja dimatikan.
   -------------------------------------------------------------------------- */
rule Defense_Evasion_Disable_Security
{
    meta:
        description = "Berusaha mematikan perlindungan Windows"
        severity = "MENCURIGAKAN"
    strings:
        $d1 = "set-mppreference -disablerealtimemonitoring" nocase
        $d2 = "add-mppreference -exclusionpath" nocase
        $d3 = "netsh advfirewall set allprofiles state off" nocase
        $d4 = "sc stop windefend" nocase
        $d5 = "sc config windefend start= disabled" nocase
        $d6 = "taskkill /f /im msmpeng" nocase
    condition:
        any of them
}

/* --------------------------------------------------------------------------
   Mengumpulkan isi clipboard atau ketikan pengguna.
   -------------------------------------------------------------------------- */
rule Input_Capture_Behavior
{
    meta:
        description = "Merekam ketikan atau isi clipboard"
        severity = "MENCURIGAKAN"
    strings:
        $k1 = "getasynckeystate" nocase
        $k2 = "setwindowshookex" nocase
        $k3 = "keylogger" nocase
        $k4 = "getclipboarddata" nocase
    condition:
        any of them
}

/* --------------------------------------------------------------------------
   Perintah yang menghapus jejak setelah beraksi.
   -------------------------------------------------------------------------- */
rule Anti_Forensics_Cleanup
{
    meta:
        description = "Menghapus log atau jejak aktivitas"
        severity = "MENCURIGAKAN"
    strings:
        $a1 = "wevtutil cl" nocase
        $a2 = "clear-eventlog" nocase
        $a3 = "del %temp%" nocase
        $a4 = "remove-item -recurse -force $env:temp" nocase
        $a5 = "cipher /w" nocase
        $a6 = "sdelete" nocase
    condition:
        any of them
}

/* --------------------------------------------------------------------------
   Pemeriksaan sanity untuk menguji mesin YARA itu sendiri. Tidak akan pernah
   cocok dengan berkas biasa, jadi aman dipakai untuk uji negatif.
   -------------------------------------------------------------------------- */
rule ScanGuard_Self_Test_Negative
{
    meta:
        description = "Tidak pernah cocok - untuk menguji bahwa mesin tidak salah lapor"
        severity = "PERLU DIPERIKSA"
    strings:
        $impossible = "scanguard-self-test-string-that-does-not-exist-9f3a7c1b"
    condition:
        $impossible
}
