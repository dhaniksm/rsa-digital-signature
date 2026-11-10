

import streamlit as st
import hmac
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import serialization

from crypto.key_manager import generate_key_pair
from crypto.identity_manager import (
    get_public_key_fingerprint,
    get_registered_identity,
    register_identity,
    list_registered_identities,
)

from crypto.signature_service import (
    sign_document,
    verify_signature as check_signature,
    calculate_sha256
)

from crypto.non_repudiation import (
    create_signed_receipt,
    verify_signed_receipt,
    append_audit_event,
    read_audit_trail,
    verify_audit_trail,
)


def format_wib_timestamp(value):
    """Format timestamp ISO menjadi waktu WIB; timestamp lama diasumsikan UTC."""
    if not value or value == "-":
        return "-"
    try:
        timestamp_text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(timestamp_text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(ZoneInfo("Asia/Jakarta")).strftime(
            "%d-%m-%Y %H:%M:%S WIB"
        )
    except (TypeError, ValueError):
        return str(value)


# =====================================================
# 1. PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="SecureDoc | Verifikasi Dokumen",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =====================================================
# 2. CUSTOM CSS - SAGE GREEN THEME
# =====================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --forest: #344638;
    --forest-light: #526A51;
    --sage: #87977A;
    --sage-light: #E8EDE3;
    --cream: #F5F3EB;
    --white: #FFFFFF;
    --text: #303B31;
    --muted: #7B8477;
    --border: #E5E7DD;
}

/* GENERAL */

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

[data-testid="stAppViewContainer"] {
    background: var(--cream);
}

[data-testid="stHeader"] {
    background: transparent;
}

.block-container {
    max-width: 1250px;
    padding: 2.3rem 3rem 3rem 3rem;
}

/* SIDEBAR */

[data-testid="stSidebar"] {
    background: var(--forest);
    border-right: 1px solid #526451;
}

[data-testid="stSidebar"] .block-container {
    padding: 2rem 1.2rem;
}

[data-testid="stSidebar"] * {
    color: #F5F5EF;
}

[data-testid="stSidebar"] hr {
    border-color: #61735F;
}

/* SIDEBAR BRAND & NAVIGATION */

.sidebar-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 4px 18px 4px;
}

.sidebar-brand-icon {
    width: 43px;
    height: 43px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #526A51;
    border: 1px solid #71866B;
    border-radius: 13px;
    font-size: 21px;
}

.sidebar-brand-name {
    color: #FFFFFF;
    font-size: 17px;
    font-weight: 800;
    letter-spacing: 1.4px;
    line-height: 1.3;
}

.sidebar-brand-caption {
    color: #C4D0BD;
    font-size: 9px;
    font-weight: 600;
    letter-spacing: 1.15px;
    margin-top: 3px;
}

.sidebar-section-label {
    color: #B9C8B1;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1.5px;
    margin: 12px 0 10px 3px;
}

[data-testid="stSidebar"] .stButton {
    margin-bottom: 7px;
}

[data-testid="stSidebar"] .stButton > button {
    width: 100%;
    min-height: 49px;
    display: flex;
    align-items: center;
    justify-content: flex-start;
    text-align: left;
    padding: 0.7rem 0.9rem;
    border-radius: 11px;
    font-size: 13px;
    font-weight: 650;
    transition: all 0.18s ease;
}

[data-testid="stSidebar"] .stButton > button[kind="secondary"] {
    color: #E8EDE3;
    background: rgba(255, 255, 255, 0.055);
    border: 1px solid rgba(210, 222, 202, 0.15);
}

[data-testid="stSidebar"] .stButton > button[kind="secondary"]:hover {
    color: #FFFFFF;
    background: #405443;
    border-color: #71866B;
    transform: translateX(2px);
}

[data-testid="stSidebar"] .stButton > button[kind="primary"] {
    color: #FFFFFF;
    background: #71866B;
    border: 1px solid #A9B99D;
    box-shadow: 0 4px 12px rgba(15, 30, 18, 0.16);
}

[data-testid="stSidebar"] .stButton > button[kind="primary"]:hover {
    color: #FFFFFF;
    background: #7F9478;
    border-color: #C4D0BD;
}

.sidebar-note {
    margin-top: 28px;
    padding: 13px 12px;
    background: rgba(255, 255, 255, 0.055);
    border: 1px solid rgba(210, 222, 202, 0.14);
    border-radius: 11px;
}

.sidebar-note-title {
    color: #FFFFFF;
    font-size: 11px;
    font-weight: 700;
    margin-bottom: 5px;
}

.sidebar-note-text {
    color: #C4D0BD;
    font-size: 10px;
    line-height: 1.7;
}

/* MAIN HEADER */

.main-title {
    font-size: 29px;
    font-weight: 800;
    color: var(--forest);
    margin-bottom: 5px;
}

.main-description {
    font-size: 13px;
    color: var(--muted);
    line-height: 1.8;
    margin-bottom: 22px;
}

.page-tag {
    display: inline-block;
    background: #E6EBDD;
    color: #536A4C;
    padding: 6px 11px;
    border-radius: 6px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    margin-bottom: 10px;
}

/* HEADINGS */

h1, h2, h3, h4 {
    color: var(--forest);
}

h3 {
    font-weight: 700;
}

/* CONTENT CARD */

[data-testid="stVerticalBlockBorderWrapper"] {
    background: #FFFFFF;
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 13px;
    box-shadow: 0 3px 12px rgba(52,70,56,0.025);
}

/* UPLOAD AREA */

[data-testid="stFileUploader"] {
    background: #FAFAF6;
    border-radius: 12px;
}

[data-testid="stFileUploaderDropzone"] {
    background: #FAFAF6;
    border: 1.5px dashed #B5C2AB;
    border-radius: 12px;
    padding: 20px 14px;
    transition: 0.2s;
}

[data-testid="stFileUploaderDropzone"]:hover {
    background: #F0F3EB;
    border-color: #87977A;
}

[data-testid="stFileUploaderDropzone"] button {
    background: #FFFFFF;
    color: #536A4C;
    border: 1px solid #C7D1BE;
    border-radius: 8px;
    font-weight: 600;
}

[data-testid="stFileUploaderDropzone"] button:hover {
    background: #E8EDE3;
    color: #344638;
    border-color: #87977A;
}

/* PRIMARY BUTTON */

.stButton > button {
    border-radius: 10px;
    min-height: 45px;
    font-weight: 600;
    transition: 0.2s;
}

.stButton > button[kind="primary"] {
    background: #657B60;
    color: #FFFFFF;
    border: none;
}

.stButton > button[kind="primary"]:hover {
    background: #4F654B;
    box-shadow: 0 4px 12px rgba(52,70,56,0.15);
}

/* DOWNLOAD BUTTON */

.stDownloadButton > button {
    background: #EEF2E9;
    color: #465B40;
    border: 1px solid #CBD5C2;
    border-radius: 9px;
    font-weight: 600;
    min-height: 43px;
}

.stDownloadButton > button:hover {
    background: #E1E9DA;
    color: #344638;
}

/* TEXT INPUT */

.stTextInput input {
    border-radius: 9px;
    border: 1px solid #D8DED2;
}

.stTextInput input:focus {
    border-color: #87977A;
    box-shadow: 0 0 0 1px #87977A;
}

/* ALERT */

[data-testid="stAlert"] {
    border-radius: 11px;
}

/* CAPTION */

[data-testid="stCaptionContainer"] {
    color: #879080;
}

/* DIVIDER */

hr {
    border-color: #E3E5DA;
}

/* FOOTER */

.footer {
    color: #92998C;
    font-size: 11px;
    text-align: center;
    padding-top: 22px;
    line-height: 1.9;
}

/* RESPONSIVE */

@media (max-width: 768px) {
    .block-container {
        padding: 1.5rem 1rem;
    }

    .main-title {
        font-size: 24px;
    }
}

</style>
""", unsafe_allow_html=True)


# =====================================================
# 3. SIDEBAR NAVIGATION
# =====================================================

menu_options = [
    ("Manajemen Kunci", "key_management"),
    ("Tanda Tangani Dokumen", "document_signing"),
    ("Verifikasi Dokumen", "document_verification"),
]

if st.session_state.get("selected_menu") not in [
    item[0] for item in menu_options
]:
    st.session_state["selected_menu"] = "Manajemen Kunci"

with st.sidebar:
    st.markdown(
        '''
        <div class="sidebar-brand">
            <div class="sidebar-brand-icon">🔐</div>
            <div>
                <div class="sidebar-brand-name">SECUREDOC</div>
                <div class="sidebar-brand-caption">DIGITAL DOCUMENT SECURITY</div>
            </div>
        </div>
        ''',
        unsafe_allow_html=True
    )

    st.divider()

    st.markdown(
        '<div class="sidebar-section-label">MENU UTAMA</div>',
        unsafe_allow_html=True
    )

    for menu_label, menu_key in menu_options:
        is_active = st.session_state["selected_menu"] == menu_label

        if st.button(
            f"{menu_label}",
            key=f"sidebar_{menu_key}",
            type="primary" if is_active else "secondary",
            use_container_width=True
        ):
            st.session_state["selected_menu"] = menu_label
            st.rerun()

    st.markdown(
        '''
        <div class="sidebar-note">
            <div class="sidebar-note-title">PROTEKSI DOKUMEN DIGITAL</div>
            <div class="sidebar-note-text">
                RSA 2048-bit &nbsp;•&nbsp; RSA-PSS<br>
                SHA-256 &nbsp;•&nbsp; Identity Verification
            </div>
        </div>
        ''',
        unsafe_allow_html=True
    )

selected_menu = st.session_state["selected_menu"]


# =====================================================
# 4. MAIN PAGE HEADER
# =====================================================

page_information = {

    "Manajemen Kunci": (
        "MANAJEMEN KUNCI",
        "Manajemen Kunci RSA",
        "Buat dan unduh pasangan kunci digital untuk proses penandatanganan dan verifikasi dokumen."
    ),

    "Tanda Tangani Dokumen": (
        "DIGITAL SIGNING",
        "Tanda Tangani Dokumen",
        "Unggah dokumen dan Private Key untuk menghasilkan tanda tangan digital."
    ),

    "Verifikasi Dokumen": (
        "DOCUMENT VERIFICATION",
        "Verifikasi Dokumen",
        "Periksa keaslian tanda tangan digital dan integritas dokumen yang telah ditandatangani."
    )

}

tag, title, description = page_information[selected_menu]

st.markdown(
    f'<div class="page-tag">{tag}</div>',
    unsafe_allow_html=True
)

st.markdown(
    f'<div class="main-title">{title}</div>',
    unsafe_allow_html=True
)

st.markdown(
    f'<div class="main-description">{description}</div>',
    unsafe_allow_html=True
)

st.divider()


# =====================================================
# 5. HELPER FUNCTION
# =====================================================

def upload_information(title, description):

    st.markdown(f"**{title}**")

    st.caption(description)


def get_configured_admin_password():
    """
    Password admin dibaca dari Streamlit secrets atau environment variable.
    Tidak ada password default yang ditanam di source code.
    """
    configured_password = ""

    try:
        configured_password = st.secrets.get("ADMIN_PASSWORD", "")
    except Exception:
        configured_password = ""

    return configured_password or os.getenv("SECUREDOC_ADMIN_PASSWORD", "")


def render_identity_registration():
    """
    Registrasi Public Key ke identitas yang dipercaya.
    Bagian ini hanya dapat diakses setelah admin memasukkan password.
    """
    with st.container(border=True):
        st.markdown("### Registrasi Identitas Penandatangan")
        st.write(
            "Daftarkan identitas pemilik Public Key agar sistem dapat "
            "mengenali penandatangan saat proses verifikasi."
        )

        configured_admin_password = get_configured_admin_password()

        if not configured_admin_password:
            st.warning(
                "Password administrator belum dikonfigurasi. "
                "Buat file `.streamlit/secrets.toml` dan isi "
                "`ADMIN_PASSWORD = \"password-admin-kuat\"`, "
                "atau atur environment variable "
                "`SECUREDOC_ADMIN_PASSWORD` sebelum menjalankan aplikasi."
            )
            return

        if not st.session_state.get("admin_authenticated", False):
            with st.form("admin_login_form"):
                admin_password_input = st.text_input(
                    "Password Administrator",
                    type="password",
                    placeholder="Masukkan password administrator"
                )
                login_submitted = st.form_submit_button(
                    "Masuk sebagai Administrator",
                    use_container_width=True
                )

            if login_submitted:
                if hmac.compare_digest(
                    admin_password_input,
                    configured_admin_password
                ):
                    st.session_state["admin_authenticated"] = True
                    st.success("Autentikasi administrator berhasil.")
                    st.rerun()
                else:
                    st.error("Password administrator tidak sesuai.")

            return

        st.success("Mode administrator aktif.")

        if st.button(
            "Keluar dari Mode Administrator",
            key="admin_logout",
        ):
            st.session_state["admin_authenticated"] = False
            st.rerun()

        st.caption(
            "Registrasi hanya boleh dilakukan oleh administrator/penerbit "
            "yang dipercaya. Jangan menerima pendaftaran identitas secara bebas."
        )

        with st.form("identity_registration_form"):
            signer_name = st.text_input(
                "Nama lengkap penandatangan",
                placeholder="Contoh: Andi Pratama"
            )
            identity_number = st.text_input(
                "NIM / NIP / ID penandatangan",
                placeholder="Contoh: 123456789"
            )
            institution = st.text_input(
                "Instansi",
                placeholder="Contoh: Universitas ..."
            )

            use_current_key = st.checkbox(
                "Gunakan Public Key yang baru dibuat pada sesi ini",
                value=bool(st.session_state.get("public_key_bytes"))
            )

            uploaded_registration_key = st.file_uploader(
                "Atau unggah Public Key (.pem)",
                type=["pem"],
                key="registration_public_key"
            )

            register_submitted = st.form_submit_button(
                "Daftarkan Identitas dan Public Key",
                use_container_width=True
            )

        if register_submitted:
            if not signer_name.strip() or not identity_number.strip() or not institution.strip():
                st.error("Nama, NIM/NIP, dan instansi wajib diisi.")
                return

            if use_current_key:
                public_key_data = st.session_state.get("public_key_bytes")
                if not public_key_data:
                    st.error(
                        "Belum ada Public Key pada sesi ini. "
                        "Generate pasangan kunci terlebih dahulu atau unggah Public Key."
                    )
                    return
            else:
                if uploaded_registration_key is None:
                    st.error("Unggah Public Key terlebih dahulu.")
                    return
                public_key_data = uploaded_registration_key.getvalue()

            try:
                public_key = serialization.load_pem_public_key(public_key_data)

                fingerprint = register_identity(
                    public_key=public_key,
                    name=signer_name.strip(),
                    identity_number=identity_number.strip(),
                    institution=institution.strip()
                )

                st.success(
                    "Identitas berhasil didaftarkan dan dihubungkan "
                    "dengan Public Key."
                )
                st.markdown("**Fingerprint Public Key (SHA-256)**")
                st.code(fingerprint)

            except ValueError as error:
                st.error(f"Registrasi gagal: {error}")
            except Exception as error:
                st.error(f"Public Key tidak valid atau registrasi gagal: {error}")

        registered = list_registered_identities()
        st.markdown("#### Identitas yang Terdaftar")
        if registered:
            st.dataframe(
                [
                    {
                        "Nama": item["name"],
                        "NIM/NIP": item["identity_number"],
                        "Instansi": item["institution"],
                        "Fingerprint": item["fingerprint"][:20] + "..."
                    }
                    for item in registered
                ],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.caption("Belum ada identitas yang didaftarkan.")


def render_audit_trail():
    """Tampilkan riwayat aktivitas kepada administrator yang sudah login."""
    if not st.session_state.get("admin_authenticated", False):
        return

    with st.container(border=True):
        st.markdown("### Audit Trail")
        st.caption(
            "Riwayat penandatanganan dan verifikasi. Rantai hash digunakan "
            "untuk mendeteksi perubahan pada catatan yang tersimpan."
        )

        try:
            events = read_audit_trail()
            chain_valid, chain_message = verify_audit_trail(events)

            if chain_valid:
                st.success(f"AUDIT TRAIL VALID — {chain_message}")
            else:
                st.error(f"AUDIT TRAIL BERMASALAH — {chain_message}")

            if events:
                rows = []
                for event in reversed(events[-100:]):
                    details = event.get("details", {})
                    rows.append({
                        "Waktu (WIB)": format_wib_timestamp(event.get("timestamp_wib") or event.get("timestamp_utc")),
                        "Aktivitas": event.get("event_type", "-"),
                        "Dokumen": details.get("document_name", "-"),
                        "Nama": details.get("signer_name", "-"),
                        "Hasil": details.get("result", "-"),
                        "Hash Catatan": event.get("event_hash", "")[:18] + "...",
                    })

                st.dataframe(rows, use_container_width=True, hide_index=True)
                st.caption("Menampilkan maksimal 100 aktivitas terbaru.")
            else:
                st.info("Belum ada aktivitas yang tercatat.")

        except Exception as error:
            st.error(f"Audit trail tidak dapat dibaca: {error}")


# =====================================================
# 6. MENU MANAJEMEN KUNCI
# =====================================================

if selected_menu == "Manajemen Kunci":

    col1, col2 = st.columns([1.5, 1])

    with col1:

        with st.container(border=True):

            st.markdown("### Buat Pasangan Kunci RSA")

            st.write(
                "Buat dua kunci digital yang saling berhubungan "
                "untuk proses tanda tangan dan verifikasi dokumen."
            )

            password = st.text_input(
                "Password Private Key (opsional)",
                type="password",
                placeholder="Masukkan password"
            )

            st.caption(
                "Password digunakan untuk mengenkripsi file Private Key."
            )

            if st.button(
                "Generate Kunci RSA",
                type="primary",
                use_container_width=True,
                key="generate_keys"
            ):

                try:

                    private_key, public_key = generate_key_pair()

                    private_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=(
                            serialization.BestAvailableEncryption(
                                password.encode("utf-8")
                            )
                            if password
                            else serialization.NoEncryption()
                        )
                    )

                    public_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    st.session_state["private_key_bytes"] = private_bytes

                    st.session_state["public_key_bytes"] = public_bytes

                    st.success(
                        "Pasangan kunci RSA berhasil dibuat!"
                    )

                except Exception as error:

                    st.error(
                        f"Gagal membuat kunci: {error}"
                    )

    with col2:

        with st.container(border=True):

            st.markdown("### Informasi Kunci")

            st.markdown("""
            **Private Key**

            Digunakan untuk membuat tanda tangan digital.
            Simpan secara rahasia.

            **Public Key**

            Digunakan oleh pihak lain untuk memverifikasi tanda tangan.

            **Penting**

            Jangan pernah membagikan Private Key kepada orang lain.
            """)

    # DOWNLOAD KEYS

    if "private_key_bytes" in st.session_state:

        st.markdown("### Kunci Berhasil Dibuat")

        col1, col2 = st.columns(2)

        with col1:

            with st.container(border=True):

                st.markdown("####Private Key")

                st.caption("KUNCI RAHASIA")

                st.write(
                    "Simpan file ini dengan aman. "
                    "Jangan membagikannya kepada orang lain."
                )

                st.download_button(
                    "Download Private Key",
                    data=st.session_state["private_key_bytes"],
                    file_name="private_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                    key="download_private"
                )

        with col2:

            with st.container(border=True):

                st.markdown("####Public Key")

                st.caption("KUNCI PUBLIK")

                st.write(
                    "Berikan file ini kepada pihak yang akan "
                    "memverifikasi dokumen Anda."
                )

                st.download_button(
                    "Download Public Key",
                    data=st.session_state["public_key_bytes"],
                    file_name="public_key.pem",
                    mime="application/x-pem-file",
                    use_container_width=True,
                    key="download_public"
                )


    st.markdown("### Pengaturan Authentication")
    render_identity_registration()
    render_audit_trail()


# =====================================================
# 7. MENU TANDA TANGANI DOKUMEN
# =====================================================

elif selected_menu == "Tanda Tangani Dokumen":

    with st.container(border=True):

        st.markdown("### Dokumen yang Akan Ditandatangani")

        upload_information(
            "Pilih Dokumen",
            "Unggah dokumen yang ingin diberi tanda tangan digital."
        )

        uploaded_document = st.file_uploader(
            "Pilih file dokumen",
            key="document_to_sign"
        )

        if uploaded_document is not None:

            st.success(
                f"Dokumen berhasil dipilih: {uploaded_document.name}"
            )

        st.divider()

        st.markdown("### Kunci Penandatangan")

        upload_information(
            "Pilih Private Key",
            "Unggah Private Key milik penerbit atau pemilik dokumen."
        )

        uploaded_private_key = st.file_uploader(
            "Pilih file Private Key",
            type=["pem"],
            key="private_key_to_sign"
        )

        if uploaded_private_key is not None:

            st.success("Private Key berhasil dipilih.")

        private_password = st.text_input(
            "Password Private Key jika dienkripsi",
            type="password",
            key="sign_password",
            placeholder="Masukkan password"
        )

        st.info(
            "Sistem akan menghitung SHA-256 dokumen, "
            "kemudian membuat tanda tangan menggunakan RSA-PSS."
        )

        if st.button(
            "Tandatangani Dokumen",
            type="primary",
            use_container_width=True,
            key="sign_document"
        ):

            st.session_state.pop("signature_bytes", None)
            st.session_state.pop("receipt_bytes", None)
            st.session_state.pop("signing_record", None)

            if (
                uploaded_document is None
                or uploaded_private_key is None
            ):

                st.error(
                    "Silakan unggah dokumen dan Private Key terlebih dahulu."
                )

            else:

                try:

                    document_data = uploaded_document.getvalue()

                    private_data = uploaded_private_key.getvalue()

                    private_key = serialization.load_pem_private_key(
                        private_data,
                        password=(
                            private_password.encode("utf-8")
                            if private_password
                            else None
                        )
                    )

                    signer_public_key = private_key.public_key()
                    signer_identity = get_registered_identity(signer_public_key)

                    if signer_identity is None:
                        st.error(
                            "Authentication gagal: Public Key pasangan Private Key "
                            "ini belum terdaftar. Daftarkan identitas dan Public Key "
                            "terlebih dahulu melalui menu Manajemen Kunci."
                        )
                    else:
                        signature = sign_document(
                            document_data,
                            private_key
                        )

                        document_hash = calculate_sha256(document_data)
                        signer_fingerprint = get_public_key_fingerprint(signer_public_key)

                        # Receipt berisi metadata penandatanganan yang ikut ditandatangani
                        # menggunakan Private Key yang sama.
                        receipt_bytes, receipt_envelope = create_signed_receipt(
                            document_data=document_data,
                            document_name=uploaded_document.name,
                            document_signature=signature,
                            private_key=private_key,
                            signer_identity=signer_identity,
                            signer_fingerprint=signer_fingerprint,
                        )

                        st.session_state["signature_bytes"] = signature
                        st.session_state["receipt_bytes"] = receipt_bytes
                        st.session_state["signing_record"] = receipt_envelope["payload"]
                        st.session_state["signed_name"] = uploaded_document.name
                        st.session_state["signed_hash"] = document_hash
                        st.session_state["signed_identity"] = signer_identity
                        st.session_state["signed_fingerprint"] = signer_fingerprint

                        audit_recorded = True
                        try:
                            append_audit_event(
                                "DOCUMENT_SIGNED",
                                {
                                    "document_name": uploaded_document.name,
                                    "document_sha256": document_hash,
                                    "signer_name": signer_identity.get("name", "-"),
                                    "signer_identity_number": signer_identity.get("identity_number", "-"),
                                    "signer_fingerprint": signer_fingerprint,
                                    "result": "SIGNED",
                                },
                            )
                        except Exception as audit_error:
                            audit_recorded = False
                            st.warning(
                                "Dokumen dan receipt berhasil ditandatangani, tetapi "
                                f"pencatatan audit gagal: {audit_error}"
                            )

                        st.session_state["signing_audit_recorded"] = audit_recorded

                        st.success(
                            "Authentication berhasil. Dokumen berhasil ditandatangani "
                            "dan bukti Non-Repudiation telah dibuat."
                        )

                except (ValueError, TypeError) as error:

                    st.error(
                        f"Private Key tidak valid atau password salah: {error}"
                    )

                except Exception as error:

                    st.error(
                        f"Gagal menandatangani dokumen: {error}"
                    )

    # SIGNING RESULT

    if "signature_bytes" in st.session_state:

        st.markdown("### Hasil Penandatanganan")

        with st.container(border=True):

            st.success(
                "Tanda tangan digital berhasil dibuat."
            )

            st.markdown("**Nama Dokumen**")

            st.code(st.session_state["signed_name"])

            st.markdown("**Hash SHA-256**")

            st.code(st.session_state["signed_hash"])

            signer_identity = st.session_state.get("signed_identity", {})
            st.markdown("**Identitas Penandatangan**")
            st.write(f"Nama: {signer_identity.get('name', '-')}")
            st.write(f"NIM/NIP: {signer_identity.get('identity_number', '-')}")
            st.write(f"Instansi: {signer_identity.get('institution', '-')}")
            st.caption("Fingerprint Public Key")
            st.code(st.session_state.get("signed_fingerprint", "-"))

            st.markdown("**File Tanda Tangan Digital**")

            st.download_button(
                " Download Signature (.sig)",
                data=st.session_state["signature_bytes"],
                file_name=st.session_state["signed_name"] + ".sig",
                mime="application/octet-stream",
                use_container_width=True,
                key="download_signature"
            )

            st.markdown("#### Bukti Penandatanganan (Non-Repudiation)")
            signing_record = st.session_state.get("signing_record", {})
            st.write(f"**Waktu penandatanganan:** {format_wib_timestamp(signing_record.get('signed_at_wib') or signing_record.get('signed_at_utc'))}")
            st.write("**Algoritma:** RSA-PSS dengan SHA-256")

            st.download_button(
                " Download Signing Receipt (.json)",
                data=st.session_state["receipt_bytes"],
                file_name=st.session_state["signed_name"] + ".receipt.json",
                mime="application/json",
                use_container_width=True,
                key="download_signing_receipt"
            )

            if st.session_state.get("signing_audit_recorded"):
                st.success("Signing record berhasil disimpan ke audit trail.")
            else:
                st.warning("Receipt tersedia, tetapi audit trail belum berhasil mencatat aktivitas ini.")

            st.caption(
                "Simpan dokumen asli, file .sig, dan signing receipt .json "
                "untuk pemeriksaan berikutnya."
            )

# =====================================================
# 8. MENU VERIFIKASI DOKUMEN
# =====================================================

elif selected_menu == "Verifikasi Dokumen":

    with st.container(border=True):

        st.markdown("### Masukkan File Verifikasi")

        st.write(
            "Unggah tiga file berikut untuk memeriksa "
            "keaslian dan integritas dokumen."
        )

        # FILE 1

        st.markdown("#### 01. Dokumen")

        upload_information(
            "Pilih Dokumen",
            "Unggah dokumen yang ingin diperiksa."
        )

        document_to_verify = st.file_uploader(
            "Pilih dokumen",
            key="document_to_verify"
        )

        if document_to_verify is not None:

            st.success(
                f"Dokumen dipilih: {document_to_verify.name}"
            )

        st.divider()

        # FILE 2

        st.markdown("#### 02. Tanda Tangan Digital")

        upload_information(
            "Pilih Signature",
            "Unggah file .sig yang dihasilkan saat proses signing."
        )

        signature_file = st.file_uploader(
            "Pilih file signature",
            key="signature_to_verify"
        )

        if signature_file is not None:

            st.success(
                f"Signature dipilih: {signature_file.name}"
            )

        st.divider()

        # FILE 3

        st.markdown("#### 03. Public Key")

        upload_information(
            "Pilih Public Key",
            "Unggah Public Key yang sesuai dengan penandatangan."
        )

        public_key_file = st.file_uploader(
            "Pilih file Public Key",
            type=["pem"],
            key="public_key_to_verify"
        )

        if public_key_file is not None:

            st.success("Public Key berhasil dipilih.")

        st.divider()

        st.markdown("#### 04. Signing Receipt (Opsional)")
        upload_information(
            "Pilih Signing Receipt",
            "Unggah file .receipt.json yang dihasilkan saat proses signing untuk memeriksa bukti Non-Repudiation."
        )
        receipt_file = st.file_uploader(
            "Pilih signing receipt (.json)",
            type=["json"],
            key="receipt_to_verify"
        )
        if receipt_file is not None:
            st.success("Signing receipt berhasil dipilih.")

        st.divider()

        st.info(
            "Dokumen, signature, dan Public Key wajib diunggah. Signing Receipt "
            "bersifat opsional, tetapi diperlukan untuk memeriksa bukti Non-Repudiation."
        )

        if st.button(
            "Verifikasi Dokumen",
            type="primary",
            use_container_width=True,
            key="verify_document"
        ):

            st.session_state.pop("verification_result", None)

            if (
                document_to_verify is None
                or signature_file is None
                or public_key_file is None
            ):

                st.error(
                    "Silakan unggah dokumen, signature, "
                    "dan Public Key terlebih dahulu."
                )

            else:

                try:

                    document_data = document_to_verify.getvalue()

                    signature_data = signature_file.getvalue()

                    public_data = public_key_file.getvalue()

                    public_key = serialization.load_pem_public_key(
                        public_data
                    )

                    signature_valid = check_signature(
                        document_data,
                        signature_data,
                        public_key
                    )

                    document_hash = calculate_sha256(
                        document_data
                    )

                    public_key_fingerprint = get_public_key_fingerprint(
                        public_key
                    )

                    registered_identity = get_registered_identity(public_key)

                    receipt_result = None
                    if receipt_file is not None:
                        try:
                            receipt_result = verify_signed_receipt(
                                receipt_data=receipt_file.getvalue(),
                                document_data=document_data,
                                document_signature=signature_data,
                                public_key=public_key,
                            )

                            receipt_signer = receipt_result["payload"].get("signer", {})
                            identity_matches_registry = bool(
                                registered_identity
                                and receipt_signer.get("name") == registered_identity.get("name")
                                and receipt_signer.get("identity_number") == registered_identity.get("identity_number")
                                and receipt_signer.get("institution") == registered_identity.get("institution")
                                and receipt_signer.get("public_key_fingerprint_sha256") == public_key_fingerprint
                            )
                            receipt_result["identity_matches_registry"] = identity_matches_registry
                            receipt_result["non_repudiation_valid"] = bool(
                                signature_valid
                                and receipt_result["valid"]
                                and identity_matches_registry
                            )
                        except ValueError as receipt_error:
                            receipt_result = {
                                "valid": False,
                                "receipt_signature_valid": False,
                                "document_hash_matches": False,
                                "signature_hash_matches": False,
                                "fingerprint_matches": False,
                                "identity_matches_registry": False,
                                "non_repudiation_valid": False,
                                "error": str(receipt_error),
                            }

                    authenticated = signature_valid and registered_identity is not None

                    audit_recorded = True
                    try:
                        append_audit_event(
                            "DOCUMENT_VERIFIED",
                            {
                                "document_name": document_to_verify.name,
                                "document_sha256": document_hash,
                                "signer_name": (registered_identity or {}).get("name", "-"),
                                "signer_identity_number": (registered_identity or {}).get("identity_number", "-"),
                                "signer_fingerprint": public_key_fingerprint,
                                "result": "VALID" if signature_valid else "INVALID",
                                "identity_registered": registered_identity is not None,
                                "receipt_provided": receipt_result is not None,
                                "receipt_valid": receipt_result["valid"] if receipt_result else None,
                            },
                        )
                    except Exception as audit_error:
                        audit_recorded = False
                        st.warning(f"Hasil verifikasi tersedia, tetapi audit trail gagal dicatat: {audit_error}")

                    st.session_state["verification_result"] = {
                        "signature_valid": signature_valid,
                        "identity": registered_identity,
                        "fingerprint": public_key_fingerprint,
                        "authenticated": authenticated,
                        "receipt": receipt_result,
                        "audit_recorded": audit_recorded,
                    }

                    st.session_state["verification_hash"] = document_hash
                    st.session_state["verification_name"] = document_to_verify.name

                    st.success("Pemeriksaan signature, identitas, dan receipt selesai.")

                except (ValueError, TypeError) as error:

                    st.error(
                        f"File atau kunci tidak valid: {error}"
                    )

                except Exception as error:

                    st.error(
                        f"Verifikasi gagal: {error}"
                    )

    # VERIFICATION RESULT

    if "verification_result" in st.session_state:

        st.markdown("### Hasil Pemeriksaan")

        with st.container(border=True):

            st.markdown("**Nama Dokumen**")

            st.code(st.session_state["verification_name"])

            st.markdown("**Hash SHA-256**")

            st.code(st.session_state["verification_hash"])

            verification = st.session_state["verification_result"]
            signature_valid = verification["signature_valid"]
            registered_identity = verification["identity"]

            st.markdown("**Fingerprint Public Key**")
            st.code(verification["fingerprint"])

            st.markdown("### Hasil Integrity Verification")
            if signature_valid:
                st.success(
                    "SIGNATURE VALID — tanda tangan cocok dengan dokumen. "
                    "Isi dokumen sesuai dengan data yang ditandatangani."
                )
            else:
                st.error(
                    "SIGNATURE INVALID — tanda tangan tidak cocok. "
                    "Dokumen mungkin berubah, signature tidak sesuai, "
                    "atau Public Key yang digunakan salah."
                )

            st.markdown("### Hasil Authentication")
            if registered_identity is not None:
                st.success("PUBLIC KEY TERDAFTAR")
                st.write(f"**Nama:** {registered_identity.get('name', '-')}")
                st.write(
                    f"**NIM/NIP:** {registered_identity.get('identity_number', '-')}"
                )
                st.write(
                    f"**Instansi:** {registered_identity.get('institution', '-')}"
                )
                st.caption(
                    f"Terdaftar pada: {format_wib_timestamp(registered_identity.get('registered_at_wib') or registered_identity.get('registered_at'))}"
                )
            else:
                st.warning(
                    "IDENTITAS BELUM TERVERIFIKASI — fingerprint Public Key "
                    "tidak ditemukan dalam daftar identitas tepercaya."
                )

            st.markdown("### Kesimpulan Pemeriksaan")
            if verification["authenticated"]:
                st.success(
                    "AUTHENTICATION BERHASIL — signature valid dan Public Key "
                    "terdaftar atas identitas penandatangan di atas."
                )
            elif signature_valid:
                st.warning(
                    "Tanda tangan valid secara kriptografis, tetapi identitas "
                    "penandatangan belum dapat dipastikan karena Public Key "
                    "belum terdaftar."
                )
            else:
                st.error(
                    "Verifikasi gagal. Sistem tidak dapat mengonfirmasi "
                    "keaslian tanda tangan maupun penandatangan dokumen."
                )

            st.markdown("### Hasil Non-Repudiation")
            receipt_result = verification.get("receipt")

            if receipt_result is None:
                st.warning(
                    "SIGNING RECEIPT BELUM DIUNGGAH — signature dan Authentication "
                    "tetap diperiksa, tetapi bukti metadata penandatanganan belum diverifikasi. "
                    "Unggah file .receipt.json dari proses signing untuk melengkapi pemeriksaan."
                )
            elif receipt_result.get("non_repudiation_valid"):
                receipt_payload = receipt_result["payload"]
                signer_data = receipt_payload.get("signer", {})
                document_data_receipt = receipt_payload.get("document", {})
                st.success(
                    "NON-REPUDIATION VALID — receipt ditandatangani oleh Private Key "
                    "yang berpasangan dengan Public Key terdaftar, dan metadata cocok."
                )
                st.write(f"**Penandatangan:** {signer_data.get('name', '-')}")
                st.write(f"**Waktu signing:** {format_wib_timestamp(receipt_payload.get('signed_at_wib') or receipt_payload.get('signed_at_utc'))}")
                st.write(f"**Hash dokumen pada receipt:** {document_data_receipt.get('sha256', '-')}")
                st.caption("Waktu berasal dari jam sistem saat signing, bukan trusted timestamp independen.")
            else:
                st.error("NON-REPUDIATION TIDAK VALID — receipt tidak cocok, tanda tangan receipt gagal, atau identitas receipt tidak sesuai dengan registry.")
                if receipt_result.get("error"):
                    st.caption(f"Detail: {receipt_result['error']}")
                st.write(f"Signature receipt valid: {'Ya' if receipt_result.get('receipt_signature_valid') else 'Tidak'}")
                st.write(f"Hash dokumen cocok: {'Ya' if receipt_result.get('document_hash_matches') else 'Tidak'}")
                st.write(f"Hash file signature cocok: {'Ya' if receipt_result.get('signature_hash_matches') else 'Tidak'}")
                st.write(f"Fingerprint Public Key cocok: {'Ya' if receipt_result.get('fingerprint_matches') else 'Tidak'}")
                st.write(f"Identitas receipt cocok dengan registry: {'Ya' if receipt_result.get('identity_matches_registry') else 'Tidak'}")

            if verification.get("audit_recorded"):
                st.caption("Aktivitas verifikasi dicatat pada audit trail lokal.")
            else:
                st.caption("Aktivitas verifikasi belum berhasil dicatat pada audit trail lokal.")

