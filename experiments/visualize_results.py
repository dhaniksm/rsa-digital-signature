import os
import pandas as pd
import matplotlib.pyplot as plt


# Lokasi file hasil benchmark
INPUT_FILE = "results/benchmark_results.csv"

# Folder penyimpanan grafik
OUTPUT_FOLDER = "results/graphs"


def load_results():
    """
    Membaca hasil eksperimen dari file CSV.
    """
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"File {INPUT_FILE} tidak ditemukan. "
            "Jalankan benchmark.py terlebih dahulu."
        )

    data = pd.read_csv(INPUT_FILE)

    required_columns = [
        "Ukuran Dokumen",
        "Ukuran Byte",
        "Rata-rata Signing (ms)",
        "Rata-rata Verification (ms)",
        "Ukuran Signature (byte)",
    ]

    missing_columns = [
        column for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Kolom CSV tidak lengkap: {missing_columns}"
        )

    return data


def create_signing_graph(data):
    """
    Membuat grafik waktu penandatanganan.
    """
    plt.figure(figsize=(9, 5))

    plt.plot(
        data["Ukuran Dokumen"],
        data["Rata-rata Signing (ms)"],
        marker="o",
    )

    plt.title("Waktu Penandatanganan Dokumen RSA")
    plt.xlabel("Ukuran Dokumen")
    plt.ylabel("Waktu Signing (ms)")
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_FOLDER}/signing_time.png",
        dpi=300,
    )

    plt.close()


def create_verification_graph(data):
    """
    Membuat grafik waktu verifikasi.
    """
    plt.figure(figsize=(9, 5))

    plt.plot(
        data["Ukuran Dokumen"],
        data["Rata-rata Verification (ms)"],
        marker="o",
    )

    plt.title("Waktu Verifikasi Tanda Tangan RSA")
    plt.xlabel("Ukuran Dokumen")
    plt.ylabel("Waktu Verification (ms)")
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_FOLDER}/verification_time.png",
        dpi=300,
    )

    plt.close()


def create_comparison_graph(data):
    """
    Membandingkan waktu signing dan verification.
    """
    plt.figure(figsize=(9, 5))

    plt.plot(
        data["Ukuran Dokumen"],
        data["Rata-rata Signing (ms)"],
        marker="o",
        label="Signing",
    )

    plt.plot(
        data["Ukuran Dokumen"],
        data["Rata-rata Verification (ms)"],
        marker="s",
        label="Verification",
    )

    plt.title("Perbandingan Waktu Signing dan Verification")
    plt.xlabel("Ukuran Dokumen")
    plt.ylabel("Waktu Pemrosesan (ms)")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()

    plt.savefig(
        f"{OUTPUT_FOLDER}/comparison_time.png",
        dpi=300,
    )

    plt.close()


def main():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    data = load_results()

    print("Data eksperimen berhasil dibaca.")
    print("\nHasil Benchmark:")
    print(data.to_string(index=False))

    create_signing_graph(data)
    create_verification_graph(data)
    create_comparison_graph(data)

    print("\nVisualisasi berhasil dibuat.")
    print(f"Lokasi grafik: {OUTPUT_FOLDER}")


if __name__ == "__main__":
    main()