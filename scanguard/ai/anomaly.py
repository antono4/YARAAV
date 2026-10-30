"""Deteksi anomali dengan model AI yang dilatih langsung di komputer pengguna.

Ini bagian AI yang paling berguna untuk keamanan, dan sama sekali tidak butuh
internet maupun kunci API.

**Masalah yang dipecahkan.** Semua mesin lain di ScanGuard mengenali *yang sudah
diketahui*: hash yang tercatat, pola yang sudah ditulis, tanda tangan yang sudah
dibuat. Malware yang baru dibuat tidak dikenali oleh satu pun dari mereka.

**Pendekatannya.** Kumpulkan ciri-ciri setiap berkas di folder yang sedang
dipindai (ukuran, entropi, jenis, rasio teks, dan seterusnya), lalu cari berkas
yang **menyimpang jauh** dari kumpulan itu. Modelnya sederhana dan memang
sengaja begitu: analisis komponen utama (PCA) yang dihitung dengan pustaka
standar. Malware yang disisipkan ke folder dokumen biasanya tampak janggal
dibanding tetangga-tetangganya, walaupun belum ada di basis data mana pun.

**Batasan yang harus jujur disebut.** Anomali bukan bukti kejahatan. Berkas yang
menyimpang bisa saja hanya berkas yang tidak biasa (basis data, cadangan,
berkas terenkripsi milik pengguna). Karena itu hasilnya selalu diberi tingkat
PERLU DIPERIKSA, tidak pernah MALWARE, dan selalu disertai alasan mengapa
berkas itu dianggap menyimpang.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field

from ..config import MAX_READ_BYTES, SEV_NOTE
from ..core import Finding, is_executable_extension, shannon_entropy

# Berapa banyak berkas teratas yang dianggap menyimpang. Menandai terlalu banyak
# membuat hasilnya tidak berguna, jadi jumlahnya dibatasi.
MAX_ANOMALIES = 15
# Berapa banyak berkas yang dibutuhkan sebelum model bisa dilatih. Di bawah ini,
# "penyimpangan" tidak bermakna karena tidak ada pembanding.
MIN_FILES = 12

# Nama ciri, dipakai saat menjelaskan mengapa sebuah berkas dianggap menyimpang.
FEATURES = [
    "ukuran",
    "entropi",
    "jenis program",
    "rasio karakter teks",
    "kedalaman folder",
    "kerapatan berkas sejenis",
]


@dataclass
class FileFeatures:
    """Ciri-ciri satu berkas yang dipakai model."""

    path: str
    size: int
    entropy: float
    is_program: float
    text_ratio: float
    depth: int
    same_extension_neighbours: int


@dataclass
class Anomaly:
    """Satu berkas yang dianggap menyimpang dari kumpulan."""

    path: str
    score: float
    reasons: list[str] = field(default_factory=list)


def _read_sample(path: str, limit: int = 256 * 1024) -> bytes:
    """Baca sebagian berkas untuk menghitung ciri.

    Hanya bagian awal yang dibaca. Berkas berukuran gigabyte tidak mungkin
    dibaca seluruhnya, dan ciri yang dipakai di sini sudah stabil pada 256 KB
    pertama.
    """
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def _text_ratio(data: bytes) -> float:
    """Bagian isi berkas yang berupa karakter teks biasa.

    Program hasil kompilasi hampir tidak punya teks; dokumen hampir seluruhnya
    teks. Angka ini memisahkan keduanya tanpa perlu membaca jenis berkasnya.
    """
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data)


def extract_features(paths: list[str]) -> list[FileFeatures]:
    """Hitung ciri untuk setiap berkas.

    Ciri "kerapatan berkas sejenis" dihitung lebih dulu karena membutuhkan
    gambaran seluruh folder: berkas yang sendirian dengan ekstensi tertentu jauh
    lebih janggal daripada berkas yang punya banyak tetangga sejenis.
    """
    extension_counts: dict[str, int] = {}
    for path in paths:
        extension = os.path.splitext(path)[1].lower()
        extension_counts[extension] = extension_counts.get(extension, 0) + 1

    features: list[FileFeatures] = []
    for path in paths:
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        sample = _read_sample(path)
        extension = os.path.splitext(path)[1].lower()
        features.append(
            FileFeatures(
                path=path,
                size=size,
                entropy=shannon_entropy(sample) if sample else 0.0,
                is_program=1.0 if is_executable_extension(path) else 0.0,
                text_ratio=_text_ratio(sample),
                depth=path.count(os.sep),
                same_extension_neighbours=extension_counts.get(extension, 1),
            )
        )
    return features


def _standardise(columns: list[list[float]]) -> tuple[list[list[float]], list[float], list[float]]:
    """Ubah setiap ciri agar rata-rata 0 dan simpangan baku 1.

    Tanpa langkah ini, ciri "ukuran" (jutaan) akan menenggelamkan ciri
    "jenis program" (0 atau 1), sehingga model hanya melihat ukuran. Ini
    kesalahan paling umum saat memakai PCA.
    """
    count = len(columns[0])
    means: list[float] = []
    deviations: list[float] = []
    normalised: list[list[float]] = []

    for column in columns:
        mean = sum(column) / count
        variance = sum((value - mean) ** 2 for value in column) / count
        deviation = math.sqrt(variance) or 1.0
        means.append(mean)
        deviations.append(deviation)
        normalised.append([(value - mean) / deviation for value in column])

    return normalised, means, deviations


def _log_transform(values: list[float]) -> list[float]:
    """Perkecil rentang ciri yang tumbuh sangat cepat (ukuran, kedalaman).

    Ukuran berkas bisa berbeda sejuta kali antar berkas. Logaritma membuat
    perbedaan itu tetap terlihat tanpa mendominasi seluruh perhitungan.
    """
    return [math.log10(value + 1.0) for value in values]


def find_anomalies(
    paths: list[str],
    max_results: int = MAX_ANOMALIES,
) -> list[Anomaly]:
    """Cari berkas yang paling menyimpang dari kumpulan berkas lain.

    Model yang dipakai adalah analisis komponen utama (PCA) dengan dua komponen
    utama. Untuk setiap berkas dihitung jarak antara nilai aslinya dan nilai
    hasil rekonstruksi: berkas yang bisa "diwakili" oleh dua komponen utama
    dianggap normal, berkas yang tidak bisa dianggap menyimpang.

    Kalau jumlah berkas kurang dari MIN_FILES, hasilnya kosong. Itu memang
    disengaja: mencari penyimpangan dari kelompok yang terlalu kecil hanya
    menghasilkan kebisingan.
    """
    if len(paths) < MIN_FILES:
        return []

    features = extract_features(paths)
    if len(features) < MIN_FILES:
        return []

    # Susun matriks ciri: baris = berkas, kolom = ciri.
    raw_columns = [
        _log_transform([float(f.size) for f in features]),
        [f.entropy for f in features],
        [f.is_program for f in features],
        [f.text_ratio for f in features],
        [float(f.depth) for f in features],
        _log_transform([float(f.same_extension_neighbours) for f in features]),
    ]
    columns, means, deviations = _standardise(raw_columns)
    count = len(features)
    dimension = len(columns)

    # Matriks kovarians antar ciri.
    covariance = [[0.0] * dimension for _ in range(dimension)]
    for i in range(dimension):
        for j in range(i, dimension):
            value = sum(columns[i][k] * columns[j][k] for k in range(count)) / count
            covariance[i][j] = value
            covariance[j][i] = value

    # Dua komponen utama, dicari dengan iterasi pangkat (power iteration).
    # Cara ini dipakai karena pustaka standar Python tidak punya fungsi eigen,
    # dan menambahkan numpy berarti menambah belasan MB ke .exe hanya untuk
    # enam ciri.
    components: list[list[float]] = []
    working = [row[:] for row in covariance]
    for _ in range(2):
        vector = _power_iteration(working)
        components.append(vector)
        # Kurangi komponen yang sudah ditemukan (deflasi) supaya komponen
        # berikutnya mengarah ke arah yang berbeda.
        working = _deflate(working, vector)

    # Rekonstruksi dan hitung sisa (residual) tiap berkas.
    scores: list[float] = []
    for k in range(count):
        original = [columns[i][k] for i in range(dimension)]
        reconstructed = [0.0] * dimension
        for vector in components:
            projection = sum(vector[i] * original[i] for i in range(dimension))
            for i in range(dimension):
                reconstructed[i] += projection * vector[i]
        residual = math.sqrt(
            sum((original[i] - reconstructed[i]) ** 2 for i in range(dimension))
        )
        scores.append(residual)

    # Ubah sisa menjadi ukuran penyimpangan: seberapa jauh dari rata-rata,
    # dibandingkan sebaran sisa seluruh berkas.
    mean_score = sum(scores) / count
    variance = sum((s - mean_score) ** 2 for s in scores) / count
    deviation = math.sqrt(variance) or 1.0

    ranked = sorted(range(count), key=lambda i: scores[i], reverse=True)
    anomalies: list[Anomaly] = []
    for index in ranked[:max_results]:
        z_score = (scores[index] - mean_score) / deviation
        # Di bawah 2 simpangan baku, berkas itu tidak cukup istimewa untuk
        # dilaporkan. Ambang ini menjaga hasilnya tetap berguna.
        if z_score < 2.0:
            continue
        anomalies.append(
            Anomaly(
                path=features[index].path,
                score=round(z_score, 2),
                reasons=_explain(features[index], features, means, deviations, columns, index),
            )
        )
    return anomalies


def _power_iteration(matrix: list[list[float]], iterations: int = 100) -> list[float]:
    """Cari vektor eigen utama dari sebuah matriks simetris.

    Dimulai dari vektor berisi satu semua, lalu berulang kali dikalikan dengan
    matriks dan dinormalkan. Cara ini konvergen ke vektor eigen dengan nilai
    eigen terbesar.
    """
    size = len(matrix)
    vector = [1.0] * size
    for _ in range(iterations):
        result = [sum(matrix[i][j] * vector[j] for j in range(size)) for i in range(size)]
        length = math.sqrt(sum(value * value for value in result))
        if length < 1e-12:
            # Matriks nol (misalnya semua berkas identik): tidak ada arah utama.
            return [1.0] + [0.0] * (size - 1)
        vector = [value / length for value in result]
    return vector


def _deflate(matrix: list[list[float]], vector: list[float]) -> list[list[float]]:
    """Kurangi satu komponen dari matriks supaya komponen berikutnya berbeda."""
    size = len(matrix)
    # Nilai eigen didekati dengan hasil kali Rayleigh.
    eigenvalue = sum(
        vector[i] * sum(matrix[i][j] * vector[j] for j in range(size))
        for i in range(size)
    )
    return [
        [matrix[i][j] - eigenvalue * vector[i] * vector[j] for j in range(size)]
        for i in range(size)
    ]


def _explain(
    feature: FileFeatures,
    all_features: list[FileFeatures],
    means: list[float],
    deviations: list[float],
    columns: list[list[float]],
    index: int,
) -> list[str]:
    """Sebutkan ciri mana yang paling membuat berkas ini menyimpang.

    Penjelasan ini penting: temuan yang tidak bisa dijelaskan alasannya tidak
    bisa ditindaklanjuti pengguna.
    """
    reasons: list[str] = []
    for position, name in enumerate(FEATURES):
        value = columns[position][index]
        # Nilai yang sudah dibakukan: 2 berarti dua simpangan baku dari rata-rata.
        if abs(value) >= 2.0:
            direction = "jauh lebih besar" if value > 0 else "jauh lebih kecil"
            reasons.append(f"{name} {direction} daripada berkas lain di folder ini")
    if not reasons:
        reasons.append("gabungan beberapa ciri menyimpang dari berkas lain")
    return reasons[:3]


def anomalies_to_findings(anomalies: list[Anomaly]) -> list[Finding]:
    """Ubah hasil deteksi anomali menjadi temuan yang bisa ditampilkan.

    Tingkatnya selalu PERLU DIPERIKSA. Ini keputusan yang disengaja: anomali
    adalah petunjuk, bukan bukti. Menaikkannya menjadi MENCURIGAKAN akan membuat
    pengguna menerima tuduhan berat hanya karena sebuah berkas kebetulan tidak
    biasa.
    """
    findings: list[Finding] = []
    for anomaly in anomalies:
        findings.append(
            Finding(
                path=anomaly.path,
                engine="AI: deteksi anomali",
                rule=f"Menyimpang dari berkas lain (skor {anomaly.score})",
                detail=(
                    "Ditemukan model AI lokal yang dilatih dari berkas di folder "
                    "ini: " + "; ".join(anomaly.reasons) + ". "
                    "Ini petunjuk, bukan bukti - periksa berkasnya bila Anda "
                    "tidak mengenalinya."
                ),
                severity=SEV_NOTE,
            )
        )
    return findings
