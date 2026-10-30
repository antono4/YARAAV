"""Pembuat berkas PE (program Windows) untuk pengujian.

Berkas PE dibuat langsung dari struktur biner, bukan diambil dari internet dan
bukan hasil kompilasi. Alasannya:

* **Selalu bisa dijalankan.** Pengujian tidak bergantung pada alat kompilasi
  silang yang mungkin tidak terpasang di komputer lain.
* **Tidak ada kode berbahaya.** Yang dibuat hanya header dan tabel impor -
  berkasnya tidak berisi instruksi mesin yang bisa dijalankan.
* **Bisa diatur.** Bagian yang ingin diuji (jumlah section, entropi, daftar
  impor) ditentukan langsung oleh pengujian, sehingga hasilnya dapat diulang.

Ini bukan pengganti uji terhadap program sungguhan - analisis PE tetap diuji
terhadap biner hasil kompilasi silang mingw-w64 saat alat itu tersedia.
"""

from __future__ import annotations

import struct

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
PE_SIGNATURE_OFFSET = 0x40
OPTIONAL_HEADER_SIZE = 240
DIRECTORY_COUNT = 16

# Nomor indeks pada tabel data directory.
DIR_IMPORT = 1

CHAR_CODE = 0x00000020
CHAR_INITIALIZED_DATA = 0x00000040
CHAR_EXECUTE = 0x20000000
CHAR_READ = 0x40000000
CHAR_WRITE = 0x80000000


def _align(value: int, boundary: int) -> int:
    """Bulatkan ke atas ke kelipatan boundary."""
    return (value + boundary - 1) // boundary * boundary


class _Section:
    def __init__(self, name: str, size: int, characteristics: int, data: bytes = b"") -> None:
        self.name = name
        self.size = size
        self.characteristics = characteristics
        self.data = data


def build_minimal_pe(
    sections: list[tuple[str, int, int]] | None = None,
    imports: list[str] | None = None,
    dll_name: str = "KERNEL32.dll",
    timestamp: int = 1_700_000_000,
    machine: int = IMAGE_FILE_MACHINE_AMD64,
    subsystem: int = IMAGE_SUBSYSTEM_WINDOWS_GUI,
    entry_section: str = ".text",
) -> bytes:
    """Susun sebuah berkas PE yang bisa dibaca pefile.

    sections: daftar (nama, ukuran, characteristics). Bila kosong, dipakai
              susunan section yang lazim.
    imports:  nama fungsi yang dimasukkan ke tabel impor.
    """
    if sections is None:
        sections = [
            (".text", 0x400, CHAR_CODE | CHAR_EXECUTE | CHAR_READ),
            (".rdata", 0x200, CHAR_INITIALIZED_DATA | CHAR_READ),
            (".data", 0x200, CHAR_INITIALIZED_DATA | CHAR_READ | CHAR_WRITE),
        ]
    if imports is None:
        # Fungsi yang lazim dipakai program Windows biasa. Ini penting supaya
        # "berkas bersih" pada pengujian benar-benar mewakili program normal,
        # bukan program yang kebetulan hanya mengimpor dua fungsi.
        imports = [
            "GetModuleHandleA", "GetCommandLineA", "GetStartupInfoA",
            "GetLastError", "SetUnhandledExceptionFilter", "HeapAlloc",
            "HeapFree", "GetProcessHeap", "Sleep", "GetTickCount",
            "QueryPerformanceCounter", "InitializeCriticalSection",
            "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
            "TlsAlloc", "TlsFree", "TlsSetValue", "TlsGetValue",
            "ExitProcess", "TerminateProcess", "GetCurrentProcessId",
            "GetCurrentThreadId", "GetSystemTimeAsFileTime", "IsDebuggerPresent",
        ]

    built = [
        _Section(name, size, chars, _section_payload(name, size))
        for name, size, chars in sections
    ]

    # --- Hitung tata letak berkas ------------------------------------------ #
    headers_size = PE_SIGNATURE_OFFSET + 4 + 20 + OPTIONAL_HEADER_SIZE + 40 * len(built)

    # Alamat maya (RVA) tiap section dihitung lebih dulu, karena tabel impor
    # perlu menyebut RVA absolut - bukan offset di dalam blob.
    rva = _align(headers_size, SECTION_ALIGNMENT)
    for section in built:
        section.rva = rva
        rva += _align(max(section.size, 1), SECTION_ALIGNMENT)
    size_of_image = rva

    # --- Tabel impor -------------------------------------------------------- #
    # Tabel impor ditaruh di awal section pertama. Data directory impor harus
    # menunjuk ke **array descriptor**, bukan ke ILT: ini kesalahan yang membuat
    # pefile membaca nol impor.
    import_rva = 0
    import_size = 0
    import_blob = b""
    if imports:
        import_blob, import_rva, import_size = _build_import_table(
            imports, dll_name, base_rva=built[0].rva
        )
        first = built[0]
        if len(import_blob) > first.size:
            first.size = _align(len(import_blob), 16)
        first.data = import_blob

    # --- Offset berkas tiap section ----------------------------------------- #
    file_offset = _align(headers_size, FILE_ALIGNMENT)
    for section in built:
        section.file_offset = file_offset
        file_offset += _align(max(section.size, len(section.data)), FILE_ALIGNMENT)

    entry_rva = 0
    for section in built:
        if section.name == entry_section:
            entry_rva = section.rva
            break

    # --- DOS header --------------------------------------------------------- #
    dos = bytearray(PE_SIGNATURE_OFFSET)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x02, 0x90)
    struct.pack_into("<H", dos, 0x04, 0x03)
    struct.pack_into("<I", dos, 0x3C, PE_SIGNATURE_OFFSET)

    # --- Tanda tangan PE dan COFF header ------------------------------------ #
    # Characteristics pada COFF header hanya 2 byte. Nilai 0x0022 berarti
    # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE. Ini berbeda dari characteristics
    # pada section, yang memakai bit 0x20000000 untuk "bisa dijalankan".
    coff_characteristics = 0x0002 | 0x0020
    coff = struct.pack(
        "<HHIIIHH",
        machine,
        len(built),
        timestamp,
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        OPTIONAL_HEADER_SIZE,
        coff_characteristics,
    )

    # --- Optional header (PE32+) -------------------------------------------- #
    directories = bytearray(8 * DIRECTORY_COUNT)
    if imports:
        struct.pack_into("<II", directories, 8 * DIR_IMPORT, import_rva, import_size)

    optional = struct.pack("<HBB", 0x20B, 14, 0)          # PE32+ / linker 14
    optional += struct.pack("<III", _align(0x400, 16), 0x400, 0)  # kode, data, bss
    optional += struct.pack("<II", entry_rva, 0)          # entry point, BaseOfCode
    optional += struct.pack("<Q", 0x140000000)            # ImageBase
    optional += struct.pack("<II", SECTION_ALIGNMENT, FILE_ALIGNMENT)
    optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)  # versi OS/image/subsystem
    optional += struct.pack("<I", 0)                      # Win32VersionValue
    optional += struct.pack("<II", size_of_image, _align(headers_size, FILE_ALIGNMENT))
    optional += struct.pack("<I", 0)                      # CheckSum
    optional += struct.pack("<HH", subsystem, 0x8160)     # Subsystem, DllCharacteristics
    optional += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    optional += struct.pack("<II", 0, DIRECTORY_COUNT)
    optional += bytes(directories)

    if len(optional) != OPTIONAL_HEADER_SIZE:
        raise AssertionError(
            f"optional header harus {OPTIONAL_HEADER_SIZE} byte, bukan {len(optional)}"
        )

    # --- Section header ------------------------------------------------------ #
    section_headers = b""
    for section in built:
        name = section.name.encode("ascii")[:8].ljust(8, b"\x00")
        raw_size = _align(max(section.size, len(section.data)), FILE_ALIGNMENT)
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            name,
            max(section.size, 1),
            section.rva,
            raw_size,
            section.file_offset,
            0,
            0,
            0,
            0,
            section.characteristics,
        )

    # --- Susun berkas -------------------------------------------------------- #
    image = bytearray(b"\x00" * file_offset)
    image[0:PE_SIGNATURE_OFFSET] = dos
    image[PE_SIGNATURE_OFFSET : PE_SIGNATURE_OFFSET + 4] = b"PE\x00\x00"
    cursor = PE_SIGNATURE_OFFSET + 4
    image[cursor : cursor + len(coff)] = coff
    cursor += len(coff)
    image[cursor : cursor + len(optional)] = optional
    cursor += len(optional)
    image[cursor : cursor + len(section_headers)] = section_headers

    for section in built:
        payload = section.data or _section_payload(section.name, section.size)
        image[section.file_offset : section.file_offset + len(payload)] = payload

    return bytes(image)


def _section_payload(name: str, size: int) -> bytes:
    """Isi section: kode berulang (entropi rendah), data nol, atau acak."""
    if name == ".text":
        # Pola berulang -> entropi rendah, seperti kode program biasa.
        return (b"\x55\x48\x89\xe5\x90\x90\xc3" * (size // 7 + 1))[:size]
    if name in (".data", ".bss"):
        return b"\x00" * size
    if name == ".rdata":
        return (b"teks konstan untuk program" * (size // 24 + 1))[:size]
    return b"\x00" * size


def _build_import_table(
    imports: list[str], dll_name: str, base_rva: int
) -> tuple[bytes, int, int]:
    """Susun tabel impor: ILT, IAT, nama fungsi, nama DLL, dan descriptor.

    Mengembalikan (isi_biner, rva_descriptor, ukuran).

    Perlu diperhatikan: **offset di dalam blob berbeda dari RVA.** Offset selalu
    dimulai dari 0 (awal blob), sedangkan RVA adalah offset ditambah base_rva
    section tempat blob itu diletakkan. Mencampur keduanya membuat descriptor
    menunjuk ke tempat yang salah, dan pefile akan membaca nol impor.
    """
    entry_size = 8  # PE32+: setiap entri 8 byte
    descriptor_size = 20

    # --- Hitung offset di dalam blob (mulai dari 0) ------------------------ #
    ilt_offset = 0
    cursor = ilt_offset + entry_size * (len(imports) + 1)

    iat_offset = cursor
    cursor += entry_size * (len(imports) + 1)

    names_offset = cursor
    name_offsets: list[int] = []
    for func in imports:
        name_offsets.append(cursor)
        cursor += 2 + len(func.encode("ascii")) + 1  # WORD panjang + teks + nol
    if cursor % 2:  # jaga perataan untuk struktur berikutnya
        cursor += 1

    dll_offset = cursor
    cursor += len(dll_name.encode("ascii")) + 1
    if cursor % 4:
        cursor += 4 - (cursor % 4)

    descriptor_offset = cursor
    blob = bytearray(cursor + descriptor_size)

    # --- Tulis isi --------------------------------------------------------- #
    for index, offset in enumerate(name_offsets):
        rva = base_rva + offset
        struct.pack_into("<Q", blob, ilt_offset + index * entry_size, rva)
        struct.pack_into("<Q", blob, iat_offset + index * entry_size, rva)

    for func, offset in zip(imports, name_offsets):
        encoded = func.encode("ascii")
        struct.pack_into("<H", blob, offset, len(encoded))
        blob[offset + 2 : offset + 2 + len(encoded)] = encoded

    dll_bytes = dll_name.encode("ascii") + b"\x00"
    blob[dll_offset : dll_offset + len(dll_bytes)] = dll_bytes

    struct.pack_into(
        "<IIIII",
        blob,
        descriptor_offset,
        base_rva + ilt_offset,   # OriginalFirstThunk -> ILT
        0,                       # TimeDateStamp
        0,                       # ForwarderChain
        base_rva + dll_offset,   # Name -> nama DLL
        base_rva + iat_offset,   # FirstThunk -> IAT
    )

    # Data directory harus menunjuk ke descriptor, bukan ke ILT.
    return bytes(blob), base_rva + descriptor_offset, descriptor_size
