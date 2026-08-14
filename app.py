import sys
import os
import json
import struct
import secrets
import hmac
import hashlib
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QProgressBar,
    QTextEdit,
    QFrame,
    QRadioButton,
    QButtonGroup,
    QGroupBox,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


# ============================================================
# POLICRYPT
# Version 1.0.0
#
# AES-256-GCM streaming encrypted container
# Scrypt password derivation
# HKDF key separation
# Per-record authentication
# Global HMAC-SHA256
# Random container ID
# ============================================================


APP_NAME = "PoliCrypt"
VERSION = "1.0.0"

MAGIC = b"POLICRYPT"

FORMAT_VERSION = 3

# ------------------------------------------------------------
# Cryptographic sizes
# ------------------------------------------------------------

SALT_SIZE = 16
CONTAINER_ID_SIZE = 16
NONCE_SIZE = 12
GCM_TAG_SIZE = 16
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
GLOBAL_MAC_SIZE = 32

# ------------------------------------------------------------
# Streaming
# ------------------------------------------------------------

CHUNK_SIZE = 1024 * 1024  # 1 MB

# Maximum plaintext contained in a single record.
MAX_RECORD_PLAINTEXT = CHUNK_SIZE + 1024

# ------------------------------------------------------------
# Scrypt
# ------------------------------------------------------------

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# ------------------------------------------------------------
# Record types
# ------------------------------------------------------------

RECORD_ENTRY = 1
RECORD_DATA = 2
RECORD_END = 3


# ============================================================
# KEY DERIVATION
# ============================================================

def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Password -> 256-bit master key using Scrypt.
    """

    if not password:
        raise ValueError(
            "Password cannot be empty."
        )

    password_bytes = password.encode(
        "utf-8"
    )

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return kdf.derive(
        password_bytes
    )


def derive_subkeys(
    master_key: bytes,
    container_id: bytes,
):
    """
    HKDF key separation.

    Master key
        |
        +---- AES-256-GCM key
        |
        +---- HMAC-SHA256 key

    Container ID is included as HKDF salt/context.
    """

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=container_id,
        info=b"PoliCrypt-v3-AES-256-GCM",
    ).derive(
        master_key
    )

    hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=HMAC_KEY_SIZE,
        salt=container_id,
        info=b"PoliCrypt-v3-HMAC-SHA256",
    ).derive(
        master_key
    )

    return aes_key, hmac_key


# ============================================================
# CONTAINER HEADER
# ============================================================

def build_header(
    salt: bytes,
    container_id: bytes,
) -> bytes:
    """
    Header:

        MAGIC             9 bytes
        VERSION           1 byte
        SALT              16 bytes
        CONTAINER ID      16 bytes
    """

    if len(salt) != SALT_SIZE:
        raise ValueError(
            "Invalid salt."
        )

    if len(container_id) != CONTAINER_ID_SIZE:
        raise ValueError(
            "Invalid container ID."
        )

    return (
        MAGIC
        + struct.pack(
            ">B",
            FORMAT_VERSION,
        )
        + salt
        + container_id
    )


def read_header(file_obj):
    magic = file_obj.read(
        len(MAGIC)
    )

    if magic != MAGIC:
        raise ValueError(
            "This is not a valid PoliCrypt container."
        )

    version_data = file_obj.read(1)

    if len(version_data) != 1:
        raise ValueError(
            "Invalid PoliCrypt header."
        )

    version = struct.unpack(
        ">B",
        version_data,
    )[0]

    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported PoliCrypt version: {version}"
        )

    salt = file_obj.read(
        SALT_SIZE
    )

    container_id = file_obj.read(
        CONTAINER_ID_SIZE
    )

    if len(salt) != SALT_SIZE:
        raise ValueError(
            "Corrupted PoliCrypt salt."
        )

    if len(container_id) != CONTAINER_ID_SIZE:
        raise ValueError(
            "Corrupted PoliCrypt container ID."
        )

    return salt, container_id


# ============================================================
# RECORD HEADER
# ============================================================

def build_record_header(
    record_type: int,
    plaintext_length: int,
) -> bytes:

    return struct.pack(
        ">BI",
        record_type,
        plaintext_length,
    )


# ============================================================
# RECORD ENCRYPTION
# ============================================================

def encrypt_record(
    aes_key: bytes,
    container_id: bytes,
    sequence: int,
    record_type: int,
    plaintext: bytes,
) -> bytes:
    """
    Encrypt a single record with AES-256-GCM.

    AAD includes:

        record header
        container ID
        sequence number

    This prevents:
        - record reordering
        - record substitution
        - record type manipulation
        - length manipulation
    """

    plaintext_length = len(
        plaintext
    )

    if plaintext_length > MAX_RECORD_PLAINTEXT:
        raise ValueError(
            "Record is too large."
        )

    record_header = build_record_header(
        record_type,
        plaintext_length,
    )

    sequence_bytes = struct.pack(
        ">Q",
        sequence,
    )

    aad = (
        MAGIC
        + struct.pack(
            ">B",
            FORMAT_VERSION,
        )
        + container_id
        + sequence_bytes
        + record_header
    )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    encryptor = Cipher(
        algorithms.AES(
            aes_key
        ),
        modes.GCM(
            nonce
        ),
    ).encryptor()

    encryptor.authenticate_additional_data(
        aad
    )

    ciphertext = (
        encryptor.update(
            plaintext
        )
        + encryptor.finalize()
    )

    payload = (
        nonce
        + ciphertext
        + encryptor.tag
    )

    return (
        record_header
        + payload
    )


# ============================================================
# RECORD DECRYPTION
# ============================================================

def decrypt_record(
    aes_key: bytes,
    container_id: bytes,
    sequence: int,
    record_type: int,
    plaintext_length: int,
    payload: bytes,
) -> bytes:

    expected_payload_size = (
        NONCE_SIZE
        + plaintext_length
        + GCM_TAG_SIZE
    )

    if len(payload) != expected_payload_size:
        raise ValueError(
            "Invalid record payload size."
        )

    nonce = payload[
        :NONCE_SIZE
    ]

    ciphertext = payload[
        NONCE_SIZE:
        -GCM_TAG_SIZE
    ]

    tag = payload[
        -GCM_TAG_SIZE:
    ]

    record_header = build_record_header(
        record_type,
        plaintext_length,
    )

    sequence_bytes = struct.pack(
        ">Q",
        sequence,
    )

    aad = (
        MAGIC
        + struct.pack(
            ">B",
            FORMAT_VERSION,
        )
        + container_id
        + sequence_bytes
        + record_header
    )

    decryptor = Cipher(
        algorithms.AES(
            aes_key
        ),
        modes.GCM(
            nonce,
            tag,
        ),
    ).decryptor()

    decryptor.authenticate_additional_data(
        aad
    )

    try:

        plaintext = (
            decryptor.update(
                ciphertext
            )
            + decryptor.finalize()
        )

    except InvalidTag:

        raise ValueError(
            "Authentication failed. "
            "Incorrect password or corrupted container."
        )

    return plaintext


# ============================================================
# RECORD WRITING
# ============================================================

def write_record(
    file_obj,
    hmac_obj,
    aes_key,
    container_id,
    sequence,
    record_type,
    plaintext,
):
    record = encrypt_record(
        aes_key=aes_key,
        container_id=container_id,
        sequence=sequence,
        record_type=record_type,
        plaintext=plaintext,
    )

    file_obj.write(
        record
    )

    # Global authentication covers
    # the complete serialized container.
    hmac_obj.update(
        record
    )


# ============================================================
# RECORD READING
# ============================================================

def read_record(
    file_obj,
):
    header = file_obj.read(5)

    if not header:
        return None

    if len(header) != 5:
        raise ValueError(
            "Truncated PoliCrypt record header."
        )

    record_type, plaintext_length = struct.unpack(
        ">BI",
        header,
    )

    if record_type not in (
        RECORD_ENTRY,
        RECORD_DATA,
        RECORD_END,
    ):
        raise ValueError(
            "Unknown PoliCrypt record type."
        )

    if plaintext_length > MAX_RECORD_PLAINTEXT:
        raise ValueError(
            "PoliCrypt record is too large."
        )

    payload_size = (
        NONCE_SIZE
        + plaintext_length
        + GCM_TAG_SIZE
    )

    payload = file_obj.read(
        payload_size
    )

    if len(payload) != payload_size:
        raise ValueError(
            "Truncated PoliCrypt record."
        )

    return (
        record_type,
        plaintext_length,
        payload,
        header,
    )


# ============================================================
# INPUT ENUMERATION
# ============================================================

def enumerate_inputs(
    inputs,
):
    """
    Convert user-selected files/folders into
    deterministic container entries.
    """

    entries = []

    for item in inputs:

        path = Path(
            item
        )

        if not path.exists():
            raise ValueError(
                f"Input does not exist:\n{path}"
            )

        if path.is_file():

            entries.append({
                "type": "file",
                "source": path,
                "relative": path.name,
            })

        elif path.is_dir():

            root_name = path.name

            entries.append({
                "type": "dir",
                "source": path,
                "relative": root_name,
            })

            for root, dirs, files in os.walk(
                path
            ):

                root_path = Path(
                    root
                )

                relative_root = (
                    root_path.relative_to(
                        path
                    )
                )

                if str(relative_root) != ".":

                    entries.append({
                        "type": "dir",
                        "source": root_path,
                        "relative": str(
                            Path(root_name)
                            / relative_root
                        ),
                    })

                for filename in files:

                    full_path = (
                        root_path
                        / filename
                    )

                    relative_file = (
                        Path(root_name)
                        / relative_root
                        / filename
                    )

                    entries.append({
                        "type": "file",
                        "source": full_path,
                        "relative": str(
                            relative_file
                        ),
                    })

    return entries


def calculate_total_size(
    entries,
):
    total = 0

    for entry in entries:

        if entry["type"] != "file":
            continue

        try:
            total += (
                entry["source"]
                .stat()
                .st_size
            )
        except OSError:
            pass

    return total


# ============================================================
# METADATA
# ============================================================

def create_metadata(
    entry,
):
    metadata = {
        "type": entry["type"],
        "path": entry["relative"],
    }

    if entry["type"] == "file":

        metadata["size"] = (
            entry["source"]
            .stat()
            .st_size
        )

    return json.dumps(
        metadata,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode(
        "utf-8"
    )


def parse_metadata(
    plaintext,
):
    try:

        metadata = json.loads(
            plaintext.decode(
                "utf-8"
            )
        )

    except Exception:

        raise ValueError(
            "Invalid encrypted metadata."
        )

    if not isinstance(
        metadata,
        dict,
    ):
        raise ValueError(
            "Invalid metadata."
        )

    if metadata.get(
        "type"
    ) not in (
        "file",
        "dir",
    ):
        raise ValueError(
            "Invalid entry type."
        )

    path = metadata.get(
        "path"
    )

    if not isinstance(
        path,
        str,
    ) or not path:

        raise ValueError(
            "Invalid entry path."
        )

    # Do not allow absolute paths.
    path_obj = Path(
        path
    )

    if path_obj.is_absolute():

        raise ValueError(
            "Absolute paths are not allowed."
        )

    if metadata["type"] == "file":

        size = metadata.get(
            "size"
        )

        if not isinstance(
            size,
            int,
        ) or size < 0:

            raise ValueError(
                "Invalid file size."
            )

    return metadata


# ============================================================
# PATH SECURITY
# ============================================================

def safe_output_path(
    output_root,
    relative_path,
):
    root = Path(
        output_root
    ).resolve()

    relative = Path(
        relative_path
    )

    if relative.is_absolute():
        raise ValueError(
            "Absolute extraction path rejected."
        )

    target = (
        root / relative
    ).resolve()

    try:

        target.relative_to(
            root
        )

    except ValueError:

        raise ValueError(
            "Unsafe extraction path detected."
        )

    return target


# ============================================================
# ENCRYPT CONTAINER
# ============================================================

def encrypt_container(
    inputs,
    output_path,
    password,
    progress_callback=None,
    status_callback=None,
):
    entries = enumerate_inputs(
        inputs
    )

    if not entries:
        raise ValueError(
            "Nothing to encrypt."
        )

    total_size = calculate_total_size(
        entries
    )

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    container_id = secrets.token_bytes(
        CONTAINER_ID_SIZE
    )

    master_key = derive_master_key(
        password,
        salt,
    )

    aes_key, hmac_key = derive_subkeys(
        master_key,
        container_id,
    )

    header = build_header(
        salt,
        container_id,
    )

    output = Path(
        output_path
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    sequence = 0
    processed = 0

    hmac_obj = hmac.new(
        hmac_key,
        digestmod=hashlib.sha256,
    )

    with open(
        output,
        "wb",
    ) as target:

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        target.write(
            header
        )

        hmac_obj.update(
            header
        )

        # ----------------------------------------------------
        # ENTRIES
        # ----------------------------------------------------

        for entry in entries:

            if status_callback:

                status_callback(
                    "Encrypting: "
                    + entry["relative"]
                )

            metadata = create_metadata(
                entry
            )

            write_record(
                file_obj=target,
                hmac_obj=hmac_obj,
                aes_key=aes_key,
                container_id=container_id,
                sequence=sequence,
                record_type=RECORD_ENTRY,
                plaintext=metadata,
            )

            sequence += 1

            # ------------------------------------------------
            # DIRECTORY
            # ------------------------------------------------

            if entry["type"] == "dir":
                continue

            # ------------------------------------------------
            # FILE
            # ------------------------------------------------

            file_path = entry[
                "source"
            ]

            with open(
                file_path,
                "rb",
            ) as source:

                while True:

                    chunk = source.read(
                        CHUNK_SIZE
                    )

                    if not chunk:
                        break

                    write_record(
                        file_obj=target,
                        hmac_obj=hmac_obj,
                        aes_key=aes_key,
                        container_id=container_id,
                        sequence=sequence,
                        record_type=RECORD_DATA,
                        plaintext=chunk,
                    )

                    sequence += 1

                    processed += len(
                        chunk
                    )

                    if progress_callback:

                        if total_size:

                            progress_callback(
                                int(
                                    (
                                        processed
                                        / total_size
                                    )
                                    * 95
                                )
                            )

        # ----------------------------------------------------
        # END RECORD
        # ----------------------------------------------------

        write_record(
            file_obj=target,
            hmac_obj=hmac_obj,
            aes_key=aes_key,
            container_id=container_id,
            sequence=sequence,
            record_type=RECORD_END,
            plaintext=b"",
        )

        # ----------------------------------------------------
        # GLOBAL HMAC
        #
        # IMPORTANT:
        # HMAC does NOT include itself.
        # ----------------------------------------------------

        global_mac = hmac_obj.digest()

        target.write(
            global_mac
        )

        target.flush()

        try:
            os.fsync(
                target.fileno()
            )
        except OSError:
            pass

    if progress_callback:
        progress_callback(
            100
        )

    if status_callback:

        status_callback(
            "Encryption completed."
        )

    return str(
        output
    )


# ============================================================
# GLOBAL HMAC VERIFICATION
# ============================================================

def verify_global_hmac(
    input_path,
    hmac_key,
    progress_callback=None,
):
    """
    Verify the global container MAC.

    Reads everything except the final 32 bytes.
    """

    file_size = (
        os.path.getsize(
            input_path
        )
    )

    minimum_size = (
        len(MAGIC)
        + 1
        + SALT_SIZE
        + CONTAINER_ID_SIZE
        + 5
        + NONCE_SIZE
        + GCM_TAG_SIZE
        + GLOBAL_MAC_SIZE
    )

    if file_size < minimum_size:

        raise ValueError(
            "Container is too small."
        )

    expected_mac = None

    hmac_obj = hmac.new(
        hmac_key,
        digestmod=hashlib.sha256,
    )

    bytes_to_authenticate = (
        file_size
        - GLOBAL_MAC_SIZE
    )

    processed = 0

    with open(
        input_path,
        "rb",
    ) as source:

        remaining = (
            bytes_to_authenticate
        )

        while remaining > 0:

            chunk_size = min(
                CHUNK_SIZE,
                remaining,
            )

            chunk = source.read(
                chunk_size
            )

            if len(chunk) != chunk_size:

                raise ValueError(
                    "Unexpected end of container."
                )

            hmac_obj.update(
                chunk
            )

            processed += len(
                chunk
            )

            remaining -= len(
                chunk
            )

            if progress_callback:

                progress_callback(
                    int(
                        (
                            processed
                            / bytes_to_authenticate
                        )
                        * 30
                    )
                )

        expected_mac = source.read(
            GLOBAL_MAC_SIZE
        )

        if len(expected_mac) != GLOBAL_MAC_SIZE:

            raise ValueError(
                "Missing global container authentication."
            )

    calculated_mac = hmac_obj.digest()

    if not hmac.compare_digest(
        calculated_mac,
        expected_mac,
    ):

        raise ValueError(
            "Global container authentication failed. "
            "Incorrect password or modified/corrupted container."
        )

    return True


# ============================================================
# CONTAINER STRUCTURE VALIDATION
# ============================================================

def validate_container(
    input_path,
    password,
    progress_callback=None,
    status_callback=None,
):
    """
    Complete verification pass.

    1. Read header.
    2. Derive keys.
    3. Verify global HMAC.
    4. Verify every AES-GCM record.
    5. Verify sequence numbers.
    6. Verify file sizes.
    7. Verify END record.

    NO PLAINTEXT FILES ARE CREATED.
    """

    input_path = Path(
        input_path
    )

    file_size = (
        input_path.stat().st_size
    )

    with open(
        input_path,
        "rb",
    ) as source:

        salt, container_id = read_header(
            source
        )

        master_key = derive_master_key(
            password,
            salt,
        )

        aes_key, hmac_key = derive_subkeys(
            master_key,
            container_id,
        )

    if status_callback:

        status_callback(
            "Checking global container authentication..."
        )

    verify_global_hmac(
        input_path,
        hmac_key,
        progress_callback=(
            lambda p: (
                progress_callback(p)
                if progress_callback
                else None
            )
        ),
    )

    if status_callback:

        status_callback(
            "Global authentication valid. "
            "Checking encrypted records..."
        )

    sequence = 0

    current_file = None
    current_file_size = 0
    current_file_received = 0

    saw_end = False

    # Size excluding global MAC.
    records_end = (
        file_size
        - GLOBAL_MAC_SIZE
    )

    with open(
        input_path,
        "rb",
    ) as source:

        salt, container_id = read_header(
            source
        )

        master_key = derive_master_key(
            password,
            salt,
        )

        aes_key, _ = derive_subkeys(
            master_key,
            container_id,
        )

        while source.tell() < records_end:

            record_start = (
                source.tell()
            )

            record = read_record(
                source
            )

            if record is None:
                break

            (
                record_type,
                plaintext_length,
                payload,
                record_header,
            ) = record

            record_end = (
                source.tell()
            )

            if record_end > records_end:

                raise ValueError(
                    "Record overlaps global authentication data."
                )

            plaintext = decrypt_record(
                aes_key=aes_key,
                container_id=container_id,
                sequence=sequence,
                record_type=record_type,
                plaintext_length=plaintext_length,
                payload=payload,
            )

            sequence += 1

            # ------------------------------------------------
            # ENTRY
            # ------------------------------------------------

            if record_type == RECORD_ENTRY:

                metadata = parse_metadata(
                    plaintext
                )

                if metadata["type"] == "file":

                    current_file = (
                        metadata["path"]
                    )

                    current_file_size = (
                        metadata["size"]
                    )

                    current_file_received = 0

                else:

                    current_file = None
                    current_file_size = 0
                    current_file_received = 0

            # ------------------------------------------------
            # DATA
            # ------------------------------------------------

            elif record_type == RECORD_DATA:

                if current_file is None:

                    raise ValueError(
                        "DATA record without FILE entry."
                    )

                current_file_received += (
                    len(plaintext)
                )

                if (
                    current_file_received
                    > current_file_size
                ):

                    raise ValueError(
                        "File data exceeds declared size."
                    )

            # ------------------------------------------------
            # END
            # ------------------------------------------------

            elif record_type == RECORD_END:

                if plaintext != b"":

                    raise ValueError(
                        "Invalid END record."
                    )

                saw_end = True

                if source.tell() != records_end:

                    raise ValueError(
                        "Unexpected data after END record."
                    )

                break

            if progress_callback:

                progress_callback(
                    30
                    + int(
                        (
                            source.tell()
                            / max(
                                records_end,
                                1,
                            )
                        )
                        * 20
                    )
                )

    if not saw_end:

        raise ValueError(
            "Container has no valid END record."
        )

    if (
        current_file is not None
        and current_file_received
        != current_file_size
    ):

        raise ValueError(
            "Final file size verification failed."
        )

    if status_callback:

        status_callback(
            "Container fully verified."
        )

    return True


# ============================================================
# EXTRACTION
# ============================================================

def extract_container(
    input_path,
    output_directory,
    password,
    progress_callback=None,
    status_callback=None,
):
    """
    Two-pass extraction.

    PASS 1:
        Complete authentication.

    PASS 2:
        Actual extraction.

    If PASS 1 fails:
        absolutely no plaintext is created.
    """

    if status_callback:

        status_callback(
            "Verifying password and container..."
        )

    validate_container(
        input_path=input_path,
        password=password,
        progress_callback=(
            lambda p: (
                progress_callback(
                    min(
                        50,
                        p,
                    )
                )
                if progress_callback
                else None
            )
        ),
        status_callback=status_callback,
    )

    if status_callback:

        status_callback(
            "Verification successful. "
            "Extracting files..."
        )

    input_path = Path(
        input_path
    )

    output_root = Path(
        output_directory
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    file_size = (
        input_path.stat().st_size
    )

    records_end = (
        file_size
        - GLOBAL_MAC_SIZE
    )

    sequence = 0

    current_handle = None
    current_file = None
    current_size = 0
    current_received = 0

    try:

        with open(
            input_path,
            "rb",
        ) as source:

            salt, container_id = read_header(
                source
            )

            master_key = derive_master_key(
                password,
                salt,
            )

            aes_key, _ = derive_subkeys(
                master_key,
                container_id,
            )

            while source.tell() < records_end:

                record = read_record(
                    source
                )

                if record is None:
                    break

                (
                    record_type,
                    plaintext_length,
                    payload,
                    record_header,
                ) = record

                plaintext = decrypt_record(
                    aes_key=aes_key,
                    container_id=container_id,
                    sequence=sequence,
                    record_type=record_type,
                    plaintext_length=plaintext_length,
                    payload=payload,
                )

                sequence += 1

                # ------------------------------------------------
                # ENTRY
                # ------------------------------------------------

                if record_type == RECORD_ENTRY:

                    if current_handle:

                        current_handle.close()

                        current_handle = None

                    metadata = parse_metadata(
                        plaintext
                    )

                    target = safe_output_path(
                        output_root,
                        metadata["path"],
                    )

                    if metadata["type"] == "dir":

                        target.mkdir(
                            parents=True,
                            exist_ok=True,
                        )

                        current_file = None
                        current_size = 0
                        current_received = 0

                    else:

                        target.parent.mkdir(
                            parents=True,
                            exist_ok=True,
                        )

                        current_file = target

                        current_size = (
                            metadata["size"]
                        )

                        current_received = 0

                        current_handle = open(
                            target,
                            "wb",
                        )

                # ------------------------------------------------
                # DATA
                # ------------------------------------------------

                elif record_type == RECORD_DATA:

                    if current_handle is None:

                        raise ValueError(
                            "DATA record without active file."
                        )

                    current_handle.write(
                        plaintext
                    )

                    current_received += (
                        len(plaintext)
                    )

                    if (
                        current_received
                        > current_size
                    ):

                        raise ValueError(
                            "Extracted data exceeds expected file size."
                        )

                # ------------------------------------------------
                # END
                # ------------------------------------------------

                elif record_type == RECORD_END:

                    if current_handle:

                        current_handle.close()

                        current_handle = None

                    break

                if progress_callback:

                    progress_callback(
                        50
                        + int(
                            (
                                source.tell()
                                / max(
                                    records_end,
                                    1,
                                )
                            )
                            * 50
                        )
                    )

        if current_handle:

            current_handle.close()

            current_handle = None

        if (
            current_file is not None
            and current_received != current_size
        ):

            raise ValueError(
                "Extracted file size mismatch."
            )

    finally:

        if current_handle:

            current_handle.close()

    if progress_callback:

        progress_callback(
            100
        )

    if status_callback:

        status_callback(
            "Extraction completed."
        )


# ============================================================
# WORKER
# ============================================================

class CryptoWorker(QThread):

    progress = pyqtSignal(int)
    status = pyqtSignal(str)

    success = pyqtSignal(str)
    failure = pyqtSignal(str)

    def __init__(
        self,
        operation,
        inputs,
        password,
        output,
    ):
        super().__init__()

        self.operation = operation
        self.inputs = inputs
        self.password = password
        self.output = output

    def run(self):

        try:

            if self.operation == "encrypt":

                result = encrypt_container(
                    inputs=self.inputs,
                    output_path=self.output,
                    password=self.password,
                    progress_callback=self.progress.emit,
                    status_callback=self.status.emit,
                )

                self.success.emit(
                    result
                )

            elif self.operation == "decrypt":

                extract_container(
                    input_path=self.inputs[0],
                    output_directory=self.output,
                    password=self.password,
                    progress_callback=self.progress.emit,
                    status_callback=self.status.emit,
                )

                self.success.emit(
                    self.output
                )

            else:

                raise ValueError(
                    "Unknown operation."
                )

        except Exception as exc:

            self.failure.emit(
                str(exc)
            )


# ============================================================
# MAIN WINDOW
# ============================================================

class PoliCryptWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.worker = None

        self.encrypt_inputs = []

        self.setWindowTitle(
            f"{APP_NAME} {VERSION}"
        )

        self.setMinimumSize(
            820,
            700,
        )

        self.build_ui()

    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )

        self.main_layout = QVBoxLayout(
            central
        )

        self.main_layout.setContentsMargins(
            30,
            25,
            30,
            15,
        )

        self.main_layout.setSpacing(
            15
        )

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        title = QLabel(
            "PoliCrypt"
        )

        title.setFont(
            QFont(
                "Segoe UI",
                30,
                QFont.Weight.Bold,
            )
        )

        title.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.main_layout.addWidget(
            title
        )

        subtitle = QLabel(
            "AES-256-GCM Streaming Container"
        )

        subtitle.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        subtitle.setStyleSheet(
            "color: #888;"
        )

        self.main_layout.addWidget(
            subtitle
        )

        # ----------------------------------------------------
        # MODE
        # ----------------------------------------------------

        mode_box = QGroupBox(
            "Operation"
        )

        mode_layout = QHBoxLayout(
            mode_box
        )

        self.encrypt_radio = QRadioButton(
            "Encrypt"
        )

        self.decrypt_radio = QRadioButton(
            "Decrypt"
        )

        self.encrypt_radio.setChecked(
            True
        )

        self.mode_group = QButtonGroup(
            self
        )

        self.mode_group.addButton(
            self.encrypt_radio
        )

        self.mode_group.addButton(
            self.decrypt_radio
        )

        mode_layout.addWidget(
            self.encrypt_radio
        )

        mode_layout.addWidget(
            self.decrypt_radio
        )

        mode_layout.addStretch()

        self.encrypt_radio.toggled.connect(
            self.switch_mode
        )

        self.main_layout.addWidget(
            mode_box
        )

        # ----------------------------------------------------
        # ENCRYPT PANEL
        # ----------------------------------------------------

        self.encrypt_panel = QWidget()

        encrypt_layout = QVBoxLayout(
            self.encrypt_panel
        )

        encrypt_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        input_box = QGroupBox(
            "Files / Folders"
        )

        input_layout = QVBoxLayout(
            input_box
        )

        self.encrypt_input_display = QTextEdit()

        self.encrypt_input_display.setReadOnly(
            True
        )

        self.encrypt_input_display.setFixedHeight(
            120
        )

        self.encrypt_input_display.setPlaceholderText(
            "Add documents and/or folders..."
        )

        input_layout.addWidget(
            self.encrypt_input_display
        )

        input_buttons = QHBoxLayout()

        self.add_documents_button = QPushButton(
            "Add Documents"
        )

        self.add_folder_button = QPushButton(
            "Add Folder"
        )

        self.clear_button = QPushButton(
            "Clear"
        )

        input_buttons.addWidget(
            self.add_documents_button
        )

        input_buttons.addWidget(
            self.add_folder_button
        )

        input_buttons.addWidget(
            self.clear_button
        )

        input_layout.addLayout(
            input_buttons
        )

        self.add_documents_button.clicked.connect(
            self.add_documents
        )

        self.add_folder_button.clicked.connect(
            self.add_folder
        )

        self.clear_button.clicked.connect(
            self.clear_encrypt
        )

        encrypt_layout.addWidget(
            input_box
        )

        # ----------------------------------------------------
        # ENCRYPT OUTPUT
        # ----------------------------------------------------

        output_box = QGroupBox(
            "Output Container"
        )

        output_layout = QHBoxLayout(
            output_box
        )

        self.encrypt_output_edit = QLineEdit()

        self.encrypt_output_edit.setPlaceholderText(
            "Select .policrypt destination..."
        )

        self.encrypt_output_button = QPushButton(
            "Browse..."
        )

        output_layout.addWidget(
            self.encrypt_output_edit
        )

        output_layout.addWidget(
            self.encrypt_output_button
        )

        self.encrypt_output_button.clicked.connect(
            self.select_encrypt_output
        )

        encrypt_layout.addWidget(
            output_box
        )

        self.main_layout.addWidget(
            self.encrypt_panel
        )

        # ----------------------------------------------------
        # DECRYPT PANEL
        # ----------------------------------------------------

        self.decrypt_panel = QWidget()

        decrypt_layout = QVBoxLayout(
            self.decrypt_panel
        )

        decrypt_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        # Container
        container_box = QGroupBox(
            "PoliCrypt Container"
        )

        container_layout = QHBoxLayout(
            container_box
        )

        self.container_edit = QLineEdit()

        self.container_edit.setReadOnly(
            True
        )

        self.container_edit.setPlaceholderText(
            "No container loaded..."
        )

        self.load_container_button = QPushButton(
            "Load Container"
        )

        container_layout.addWidget(
            self.container_edit
        )

        container_layout.addWidget(
            self.load_container_button
        )

        self.load_container_button.clicked.connect(
            self.load_container
        )

        decrypt_layout.addWidget(
            container_box
        )

        # Extract
        extract_box = QGroupBox(
            "Extract To"
        )

        extract_layout = QHBoxLayout(
            extract_box
        )

        self.extract_directory_edit = QLineEdit()

        self.extract_directory_edit.setReadOnly(
            True
        )

        self.extract_directory_edit.setPlaceholderText(
            "Select extraction directory..."
        )

        self.extract_directory_button = QPushButton(
            "Browse..."
        )

        extract_layout.addWidget(
            self.extract_directory_edit
        )

        extract_layout.addWidget(
            self.extract_directory_button
        )

        self.extract_directory_button.clicked.connect(
            self.select_extract_directory
        )

        decrypt_layout.addWidget(
            extract_box
        )

        self.main_layout.addWidget(
            self.decrypt_panel
        )

        self.decrypt_panel.hide()

        # ----------------------------------------------------
        # PASSWORD
        # ----------------------------------------------------

        password_box = QGroupBox(
            "Password"
        )

        password_layout = QHBoxLayout(
            password_box
        )

        self.password_edit = QLineEdit()

        self.password_edit.setEchoMode(
            QLineEdit.EchoMode.Password
        )

        self.password_edit.setPlaceholderText(
            "Enter password..."
        )

        self.show_password_button = QPushButton(
            "Show"
        )

        self.show_password_button.setCheckable(
            True
        )

        self.show_password_button.toggled.connect(
            self.toggle_password
        )

        password_layout.addWidget(
            self.password_edit
        )

        password_layout.addWidget(
            self.show_password_button
        )

        self.main_layout.addWidget(
            password_box
        )

        # ----------------------------------------------------
        # ACTION
        # ----------------------------------------------------

        self.action_button = QPushButton(
            "ENCRYPT"
        )

        self.action_button.setMinimumHeight(
            52
        )

        self.action_button.setFont(
            QFont(
                "Segoe UI",
                12,
                QFont.Weight.Bold,
            )
        )

        self.action_button.clicked.connect(
            self.start_operation
        )

        self.main_layout.addWidget(
            self.action_button
        )

        # ----------------------------------------------------
        # PROGRESS
        # ----------------------------------------------------

        self.progress_bar = QProgressBar()

        self.progress_bar.setRange(
            0,
            100,
        )

        self.progress_bar.setValue(
            0
        )

        self.main_layout.addWidget(
            self.progress_bar
        )

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        self.status_label = QLabel(
            "Ready."
        )

        self.status_label.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.status_label.setStyleSheet(
            "color: #777;"
        )

        self.main_layout.addWidget(
            self.status_label
        )

        # ----------------------------------------------------
        # FOOTER
        # ----------------------------------------------------

        line = QFrame()

        line.setFrameShape(
            QFrame.Shape.HLine
        )

        line.setFrameShadow(
            QFrame.Shadow.Sunken
        )

        self.main_layout.addWidget(
            line
        )

        footer = QLabel(
            "© 2026 Šamec Uglješa. All rights reserved."
        )

        footer.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        footer.setStyleSheet(
            "color: #777; font-size: 11px;"
        )

        self.main_layout.addWidget(
            footer
        )

    # ========================================================
    # MODE SWITCH
    # ========================================================

    def switch_mode(
        self,
        encrypt,
    ):

        self.progress_bar.setValue(
            0
        )

        self.password_edit.clear()

        if encrypt:

            self.encrypt_panel.show()

            self.decrypt_panel.hide()

            self.action_button.setText(
                "ENCRYPT"
            )

            self.status_label.setText(
                "Ready to encrypt."
            )

        else:

            self.encrypt_panel.hide()

            self.decrypt_panel.show()

            self.action_button.setText(
                "EXTRACT"
            )

            self.status_label.setText(
                "Load a PoliCrypt container."
            )

    # ========================================================
    # ENCRYPT INPUT
    # ========================================================

    def add_documents(self):

        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Documents",
            "",
            "All Files (*.*)",
        )

        if not files:
            return

        for file_path in files:

            if file_path not in self.encrypt_inputs:

                self.encrypt_inputs.append(
                    file_path
                )

        self.refresh_encrypt_list()

    def add_folder(self):

        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder",
        )

        if not folder:
            return

        if folder not in self.encrypt_inputs:

            self.encrypt_inputs.append(
                folder
            )

        self.refresh_encrypt_list()

    def refresh_encrypt_list(self):

        self.encrypt_input_display.clear()

        for item in self.encrypt_inputs:

            self.encrypt_input_display.append(
                item
            )

    def clear_encrypt(self):

        self.encrypt_inputs.clear()

        self.encrypt_input_display.clear()

        self.status_label.setText(
            "Encryption input cleared."
        )

    # ========================================================
    # ENCRYPT OUTPUT
    # ========================================================

    def select_encrypt_output(self):

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PoliCrypt Container",
            "",
            "PoliCrypt Container (*.policrypt)",
        )

        if not path:
            return

        if not path.lower().endswith(
            ".policrypt"
        ):

            path += ".policrypt"

        self.encrypt_output_edit.setText(
            path
        )

    # ========================================================
    # LOAD CONTAINER
    # ========================================================

    def load_container(self):

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load PoliCrypt Container",
            "",
            "PoliCrypt Container (*.policrypt)",
        )

        if not path:
            return

        if not path.lower().endswith(
            ".policrypt"
        ):

            QMessageBox.warning(
                self,
                "Invalid Container",
                "Please select a .policrypt container.",
            )

            return

        self.container_edit.setText(
            path
        )

        self.status_label.setText(
            "Container loaded."
        )

    # ========================================================
    # EXTRACT DIRECTORY
    # ========================================================

    def select_extract_directory(self):

        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Extraction Directory",
        )

        if not directory:
            return

        self.extract_directory_edit.setText(
            directory
        )

        self.status_label.setText(
            "Extraction directory selected."
        )

    # ========================================================
    # PASSWORD
    # ========================================================

    def toggle_password(
        self,
        checked,
    ):

        if checked:

            self.password_edit.setEchoMode(
                QLineEdit.EchoMode.Normal
            )

            self.show_password_button.setText(
                "Hide"
            )

        else:

            self.password_edit.setEchoMode(
                QLineEdit.EchoMode.Password
            )

            self.show_password_button.setText(
                "Show"
            )

    # ========================================================
    # START
    # ========================================================

    def start_operation(self):

        if self.worker is not None:
            return

        password = (
            self.password_edit.text()
        )

        if not password:

            QMessageBox.warning(
                self,
                "Password Required",
                "Enter the password.",
            )

            self.password_edit.setFocus()

            return

        # ----------------------------------------------------
        # ENCRYPT
        # ----------------------------------------------------

        if self.encrypt_radio.isChecked():

            if not self.encrypt_inputs:

                QMessageBox.warning(
                    self,
                    "Nothing Selected",
                    "Add at least one document or folder.",
                )

                return

            output = (
                self.encrypt_output_edit
                .text()
                .strip()
            )

            if not output:

                QMessageBox.warning(
                    self,
                    "Output Required",
                    "Select the destination .policrypt file.",
                )

                return

            for item in self.encrypt_inputs:

                if not Path(item).exists():

                    QMessageBox.warning(
                        self,
                        "Invalid Input",
                        f"Input does not exist:\n{item}",
                    )

                    return

            output_path = Path(
                output
            )

            if output_path.exists():

                answer = QMessageBox.question(
                    self,
                    "Overwrite Container?",
                    "The selected container already exists.\n\n"
                    "Overwrite it?",
                    QMessageBox.StandardButton.Yes
                    | QMessageBox.StandardButton.No,
                )

                if (
                    answer
                    != QMessageBox.StandardButton.Yes
                ):

                    return

            operation = "encrypt"

            inputs = list(
                self.encrypt_inputs
            )

        # ----------------------------------------------------
        # DECRYPT
        # ----------------------------------------------------

        else:

            container = (
                self.container_edit
                .text()
                .strip()
            )

            if not container:

                QMessageBox.warning(
                    self,
                    "Container Required",
                    "Load a PoliCrypt container first.",
                )

                return

            container_path = Path(
                container
            )

            if not container_path.is_file():

                QMessageBox.warning(
                    self,
                    "Invalid Container",
                    "The selected container does not exist.",
                )

                return

            if (
                container_path.suffix.lower()
                != ".policrypt"
            ):

                QMessageBox.warning(
                    self,
                    "Invalid Container",
                    "Only .policrypt containers are supported.",
                )

                return

            output = (
                self.extract_directory_edit
                .text()
                .strip()
            )

            if not output:

                QMessageBox.warning(
                    self,
                    "Extraction Directory Required",
                    "Select the directory where the "
                    "container should be extracted.",
                )

                return

            operation = "decrypt"

            inputs = [
                str(container_path)
            ]

        # ----------------------------------------------------
        # START WORKER
        # ----------------------------------------------------

        self.set_busy(
            True
        )

        self.progress_bar.setValue(
            0
        )

        self.worker = CryptoWorker(
            operation=operation,
            inputs=inputs,
            password=password,
            output=output,
        )

        self.worker.progress.connect(
            self.progress_bar.setValue
        )

        self.worker.status.connect(
            self.status_label.setText
        )

        self.worker.success.connect(
            self.operation_success
        )

        self.worker.failure.connect(
            self.operation_failure
        )

        self.worker.finished.connect(
            self.worker_finished
        )

        self.worker.start()

    # ========================================================
    # RESULTS
    # ========================================================

    def operation_success(
        self,
        result,
    ):

        self.progress_bar.setValue(
            100
        )

        if self.encrypt_radio.isChecked():

            QMessageBox.information(
                self,
                "PoliCrypt",
                "Encryption completed successfully.\n\n"
                f"Container:\n{result}",
            )

            self.status_label.setText(
                "Encryption completed."
            )

        else:

            QMessageBox.information(
                self,
                "PoliCrypt",
                "Container authenticated and "
                "extracted successfully.\n\n"
                f"Directory:\n{result}",
            )

            self.status_label.setText(
                "Extraction completed."
            )

    def operation_failure(
        self,
        error,
    ):

        self.progress_bar.setValue(
            0
        )

        QMessageBox.critical(
            self,
            "PoliCrypt Error",
            "Operation failed.\n\n"
            f"{error}",
        )

        self.status_label.setText(
            "Operation failed."
        )

    # ========================================================
    # WORKER
    # ========================================================

    def worker_finished(self):

        self.set_busy(
            False
        )

        self.password_edit.clear()

        if self.worker:

            self.worker.deleteLater()

        self.worker = None

    # ========================================================
    # UI BUSY
    # ========================================================

    def set_busy(
        self,
        busy,
    ):

        self.encrypt_radio.setEnabled(
            not busy
        )

        self.decrypt_radio.setEnabled(
            not busy
        )

        self.add_documents_button.setEnabled(
            not busy
        )

        self.add_folder_button.setEnabled(
            not busy
        )

        self.clear_button.setEnabled(
            not busy
        )

        self.load_container_button.setEnabled(
            not busy
        )

        self.encrypt_output_button.setEnabled(
            not busy
        )

        self.extract_directory_button.setEnabled(
            not busy
        )

        self.password_edit.setEnabled(
            not busy
        )

        self.show_password_button.setEnabled(
            not busy
        )

        self.action_button.setEnabled(
            not busy
        )


# ============================================================
# MAIN
# ============================================================

def main():

    app = QApplication(
        sys.argv
    )

    app.setApplicationName(
        APP_NAME
    )

    app.setApplicationVersion(
        VERSION
    )

    app.setStyle(
        "Fusion"
    )

    # Application icon
    icon_path = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "app.png"
    )

    app.setWindowIcon(
        QIcon(icon_path)
    )

    window = PoliCryptWindow()

    # Window icon
    window.setWindowIcon(
        QIcon(icon_path)
    )

    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":
    main()