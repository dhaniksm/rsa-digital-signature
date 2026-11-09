import os
import csv
import time
import statistics

from crypto.key_manager import generate_key_pair
from crypto.signature_service import (
    sign_document,
    verify_signature,
)


# Konfigurasi eksperimen
DOCUMENT_SIZES = {
    "1 KB": 1024,
    "10 KB": 10 * 1024,
    "100 KB": 100 * 1024,
    "1 MB": 1024 * 1024,
    "5 MB": 5 * 1024 * 1024,
}

REPETITIONS = 10


def benchmark_signing(document, private_key):
    """
    Mengukur waktu proses penandatanganan dokumen.
    """
    execution_times = []
    signature = None

    for _ in range(REPETITIONS):
        start_time = time.perf_counter()

        signature = sign_document(
            document,
            private_key
        )

        end_time = time.perf_counter()

        execution_times.append(
            (end_time - start_time) * 1000
        )

    average_time = statistics.mean(execution_times)

    return average_time, signature


def benchmark_verification(
    document,
    signature,
    public_key
):
    """
    Mengukur waktu proses verifikasi tanda tangan.
    """
    execution_times = []

    for _ in range(REPETITIONS):
        start_time = time.perf_counter()

        result = verify_signature(
            document,
            signature,
            public_key
        )

        end_time = time.perf_counter()

        execution_times.append(
            (end_time - start_time) * 1000
        )

        if not result:
            raise RuntimeError(
                "Verifikasi tanda tangan gagal."
            )

    average_time = statistics.mean(execution_times)

    return average_time


def run_benchmark():
    print("Memulai eksperimen RSA Digital Signature...")
    print("Membuat pasangan kunci RSA 2048-bit...")

    private_key, public_key = generate_key_pair()

    results = []

    for size_name, size_bytes in DOCUMENT_SIZES.items():
        print(f"\nMenguji dokumen berukuran {size_name}...")

        # Membuat data dokumen secara acak
        document = os.urandom(size_bytes)

        # Mengukur waktu penandatanganan
        signing_time, signature = benchmark_signing(
            document,
            private_key
        )

        # Mengukur waktu verifikasi
        verification_time = benchmark_verification(
            document,
            signature,
            public_key
        )

        result = {
            "Ukuran Dokumen": size_name,
            "Ukuran Byte": size_bytes,
            "Jumlah Pengujian": REPETITIONS,
            "Rata-rata Signing (ms)": round(
                signing_time, 4
            ),
            "Rata-rata Verification (ms)": round(
                verification_time, 4
            ),
            "Ukuran Signature (byte)": len(signature),
        }

        results.append(result)

        print(
            f"Signing: {signing_time:.4f} ms"
        )

        print(
            f"Verification: {verification_time:.4f} ms"
        )

        print(
            f"Signature: {len(signature)} byte"
        )

    # Menyimpan hasil eksperimen ke CSV
    os.makedirs("results", exist_ok=True)

    output_file = "results/benchmark_results.csv"

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=results[0].keys()
        )

        writer.writeheader()
        writer.writerows(results)

    print("\nEksperimen selesai.")
    print(f"Hasil disimpan di: {output_file}")


if __name__ == "__main__":
    run_benchmark()