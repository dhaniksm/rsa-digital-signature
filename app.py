import streamlit as st
from cryptography.hazmat.primitives import serialization
from crypto.key_manager import (generate_key_pair, save_private_key, save_public_key)
from crypto.signature_service import (sign_document, verify_signature, calculate_sha256)

st.set_page_config(page_title="RSA Digital Signature", layout="centered")
st.title("RSA Digital Signature")
st.write("Aplikasi tanda tangan digital berbasis RSA untuk memverifikasi keaslian dan integritas dokumen.")
st.info("Aplikasi ini menggunakan RSA 2048-bit, RSA-PSS, dan SHA-256. Tanda tangan digital tidak mengenkripsi isi dokumen.")


tab_keys, tab_sign, tab_verify = st.tabs(
    [
        "Manajemen Kunci",
        "Tanda Tangani Dokumen",
        "Verifikasi Dokumen",
    ]
)

with tab_keys:
    st.header("Pembuatan Pasangan Kunci RSA")
    st.write("Buat pasangan kunci yang terdiri dari kunci privat untuk menandatangani dokumen dan kunci publik untuk memverifikasi tanda tangan.")

    password = st.text_input(
        "Password untuk melindungi kunci privat",
        type="password",
        help=("Kosongkan jika ingin menyimpan kunci privat tanpa enkripsi. Untuk penggunaan nyata, sebaiknya gunakan password yang kuat."),
    )

    if st.button("Generate Kunci RSA", key="generate_keys"):
        try:
            private_key, public_key = generate_key_pair()

            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=(
                    serialization.BestAvailableEncryption(
                        password.encode("utf-8")
                    )
                    if password
                    else serialization.NoEncryption()
                ),
            )

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=(
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ),
            )

            st.session_state["private_key_bytes"] = (
                private_key_bytes
            )
            st.session_state["public_key_bytes"] = (
                public_key_bytes
            )

            st.success("Pasangan kunci RSA berhasil dibuat.")

        except Exception as error:
            st.error(
                f"Gagal membuat pasangan kunci: {error}"
            )

    if "private_key_bytes" in st.session_state:
        st.subheader("Unduh Kunci")

        st.download_button(
            label="Unduh Kunci Privat",
            data=st.session_state["private_key_bytes"],
            file_name="private_key.pem",
            mime="application/x-pem-file",
            key="download_private_key",
        )

        st.warning("Jaga kerahasiaan kunci privat. Jangan membagikannya kepada orang lain.")

        st.download_button(
            label="Unduh Kunci Publik",
            data=st.session_state["public_key_bytes"],
            file_name="public_key.pem",
            mime="application/x-pem-file",
            key="download_public_key",
        )

with tab_sign:
    st.header("Tanda Tangani Dokumen")
    st.write("Unggah dokumen dan kunci privat untuk membuat tanda tangan digital.")

    uploaded_document = st.file_uploader(
        "Pilih dokumen",
        key="document_to_sign",
    )

    uploaded_private_key = st.file_uploader(
        "Pilih kunci privat (.pem)",
        type=["pem"],
        key="private_key_to_sign",
    )

    private_key_password = st.text_input(
        "Password kunci privat jika dienkripsi",
        type="password",
        key="private_key_password",
    )

    if st.button(
        "Tandatangani Dokumen",
        key="sign_document",
    ):
        if (
            uploaded_document is None
            or uploaded_private_key is None
        ):
            st.error(
                "Unggah dokumen dan kunci privat terlebih dahulu."
            )
        else:
            try:
                document_data = uploaded_document.getvalue()
                private_key_data = (
                    uploaded_private_key.getvalue()
                )

                private_key = (
                    serialization.load_pem_private_key(
                        private_key_data,
                        password=(
                            private_key_password.encode("utf-8")
                            if private_key_password
                            else None
                        ),
                    )
                )

                signature = sign_document(
                    document_data,
                    private_key,
                )

                document_hash = calculate_sha256(
                    document_data
                )

                st.session_state["signature_bytes"] = signature
                st.session_state["signed_document_name"] = (
                    uploaded_document.name
                )

                st.success(
                    "Tanda tangan digital berhasil dibuat."
                )

                st.write("**Nama dokumen:**")
                st.code(uploaded_document.name)

                st.write("**SHA-256 dokumen:**")
                st.code(document_hash)

                st.download_button(
                    label="Unduh Tanda Tangan (.sig)",
                    data=signature,
                    file_name=(
                        uploaded_document.name + ".sig"
                    ),
                    mime="application/octet-stream",
                    key="download_signature",
                )

            except (ValueError, TypeError) as error:
                st.error(f"Kunci privat tidak valid atau password tidak sesuai. Detail: {error}")

            except Exception as error:
                st.error(f"Gagal menandatangani dokumen: {error}")

with tab_verify:
    st.header("Verifikasi Tanda Tangan Digital")

    st.write(
        "Unggah dokumen, file tanda tangan (.sig), dan "
        "kunci publik yang sesuai."
    )

    document_to_verify = st.file_uploader(
        "Pilih dokumen yang akan diverifikasi",
        key="document_to_verify",
    )

    signature_file = st.file_uploader(
        "Pilih file tanda tangan (.sig)",
        key="signature_to_verify",
    )

    public_key_file = st.file_uploader(
        "Pilih kunci publik (.pem)",
        type=["pem"],
        key="public_key_to_verify",
    )

    if st.button(
        "Verifikasi Dokumen",
        key="verify_document",
    ):
        if (
            document_to_verify is None
            or signature_file is None
            or public_key_file is None
        ):
            st.error(
                "Pastikan ketiga file telah diunggah."
            )
        else:
            try:
                document_data = (
                    document_to_verify.getvalue()
                )
                signature_data = signature_file.getvalue()
                public_key_data = public_key_file.getvalue()

                public_key = (
                    serialization.load_pem_public_key(
                        public_key_data
                    )
                )

                is_valid = verify_signature(
                    document_data,
                    signature_data,
                    public_key,
                )

                st.write("**Nama dokumen:**")
                st.code(document_to_verify.name)

                st.write("**SHA-256 dokumen:**")
                st.code(calculate_sha256(document_data))

                if is_valid:
                    st.success("TANDA TANGAN VALID. Dokumen sesuai dengan tanda tangan yang diverifikasi.")
                    st.write("Tanda tangan cocok dengan isi dokumen dan kunci publik yang digunakan.")
                else:
                    st.error("TANDA TANGAN TIDAK VALID. Dokumen mungkin telah diubah, tanda tangan tidak cocok, atau kunci publik salah.")

            except (ValueError, TypeError) as error:
                st.error(f"File atau kunci tidak valid. Periksa kembali file yang digunakan. Detail: {error}")

            except Exception as error:
                st.error(f"Verifikasi gagal: {error}")

st.divider()

st.caption("Proyek akademik Kriptografi. Implementasi RSA-PSS dengan SHA-256 menggunakan pustaka cryptography.")