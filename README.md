# 🔐 PoliCrypt  
### Version 1.0 – Local • Zero-Knowledge • Folder & File Encryption  

<p align="center">

![Python](https://img.shields.io/badge/Python-3.x-blue)
![UI](https://img.shields.io/badge/UI-PyQt6-green)
![Cryptography](https://img.shields.io/badge/Crypto-AES--GCM-red)
![Encryption](https://img.shields.io/badge/Encryption-AES--256-red)
![KDF](https://img.shields.io/badge/KDF-Scrypt-orange)
![Authentication](https://img.shields.io/badge/Authentication-HMAC--SHA256-black)
![Container](https://img.shields.io/badge/Container-.policrypt-blue)
![Security](https://img.shields.io/badge/Security-Zero--Knowledge-black)
![Storage](https://img.shields.io/badge/Storage-Local--Only-orange)
![License](https://img.shields.io/badge/License-GPLv3-brightgreen)

</p>

---

## 🛡 About PoliCrypt

**PoliCrypt** is a **secure local file and folder encryption application** that allows users to encrypt individual documents, multiple files, or entire folders into a protected `.policrypt` container.

The application uses **AES-256-GCM encryption** together with **Scrypt password-based key derivation**, **HKDF-SHA256 key separation**, and **HMAC-SHA256 container authentication**.

PoliCrypt is designed around a simple security principle:

**Without the correct password, successful authenticated decryption must never occur.**

The application is fully local, written in Python with PyQt6, and does not require cloud storage, online accounts, or remote authentication services.

---

## 🎯 Intended For

- 👤 Individuals who want **secure local file encryption**
- 📁 Users who want to encrypt **entire folders**
- 📄 Users who need to protect **sensitive documents**
- 💾 Users who want to create **encrypted local backups**
- 🔐 Security enthusiasts who prefer **offline encryption**
- 💻 Developers and security researchers
- 🏢 Small organizations requiring **local encrypted storage**

---

## ⚡ Key Advantages

- 🖥 **Local Only** – Data never leaves your computer
- 🔐 **AES-256-GCM** – Strong authenticated encryption
- 🔑 **Scrypt** – Password-based key derivation
- 🧬 **HKDF-SHA256** – Cryptographic key separation
- 🛡 **HMAC-SHA256** – Global container authentication
- 🆔 **Container ID** – Unique identity for every encrypted container
- 🌊 **Streaming Encryption** – Large files are processed in chunks
- 📁 **Folder Encryption** – Entire directory structures can be encrypted
- 📄 **Multiple Files** – Multiple documents can be stored in one container
- 🚫 **No Password Recovery** – No hidden master password or backdoor
- 💰 **Free & Open-Source** – GPLv3 licensed

---

## 🏗 Technical Architecture

**Encryption Flow:**

```text
Password
   ↓
Scrypt + Random Salt
   ↓
256-bit Master Key
   ↓
HKDF-SHA256
   ↓
AES-256 Key + HMAC Key
   ↓
AES-256-GCM Encryption
   ↓
Streaming Container
   ↓
Global HMAC-SHA256
   ↓
.policrypt Container
```

---

## 📷 Application Screenshots

![PoliCrypt UI](gui.png)

---

## 📦 Container Architecture

PoliCrypt does not encrypt an entire folder by loading everything into memory.

Instead, files are processed using a **streaming container format**.

```text
Selected Folder / Files
        ↓
Filesystem Enumeration
        ↓
Container Header
        ↓
ENTRY Record
        ↓
DATA Record
        ↓
DATA Record
        ↓
DATA Record
        ↓
ENTRY Record
        ↓
DATA Record
        ↓
END Record
        ↓
Global HMAC-SHA256
        ↓
.policrypt
```

---

## 🔐 Security Model

Password → Scrypt + Random Salt → Master Key → HKDF-SHA256 → AES-256 Key + HMAC Key → AES-256-GCM → Authenticated Container

### Security Features

- Scrypt password-based key derivation
- Random cryptographic salt
- AES-256-GCM authenticated encryption
- Random nonce for encrypted records
- HKDF-SHA256 key separation
- HMAC-SHA256 global container authentication
- Unique Container ID
- Authenticated container records
- Streaming encryption and decryption
- Password is never stored in plaintext
- No cloud storage
- No password recovery mechanism
- No hidden master key
- No remote authentication service

---

## 🔄 Application Life-Cycle

1. Launch PoliCrypt
2. Select **Encrypt** or **Decrypt**
3. Select files or folders for encryption
4. Enter encryption password
5. Create `.policrypt` container
6. Store the encrypted container securely
7. When required, select **Decrypt**
8. Load the `.policrypt` container
9. Enter the original password
10. Select extraction directory
11. Authenticate the container
12. Extract the original files

---

## ⭐ Unique Values

- Data never leaves your computer
- AES-256 authenticated encryption
- Scrypt password protection
- Global container authentication
- Unique Container ID
- Streaming file processing
- Entire folders can be encrypted
- Multiple documents can be stored in one container
- Dedicated Encrypt / Decrypt interface
- No cloud dependency
- No password recovery
- Single `app.py` architecture
- Windows `.exe` support
- Full source-code transparency

---

## ⚙ Functionalities

### 🔐 Encrypt Files

1. Open **PoliCrypt**
2. Select **Encrypt**
3. Click **Add Document**
4. Select one or more files
5. Enter a strong password
6. Select the output `.policrypt` container
7. Click **Encrypt**

The selected files are encrypted into a single authenticated container.

---

### 📁 Encrypt Folder

1. Open **PoliCrypt**
2. Select **Encrypt**
3. Click **Add Folder**
4. Select the folder
5. Enter a strong password
6. Select the output container
7. Click **Encrypt**

The complete directory structure is preserved inside the encrypted container.

Example:

```text
Documents/
├── Report.pdf
├── Contract.docx
└── Images/
    ├── image1.jpg
    └── image2.jpg
```

After encryption:

```text
Documents.policrypt
```

---

### 📄 Multiple Documents

PoliCrypt can encrypt multiple independent documents into a single container.

Example:

```text
Report.pdf
Contract.docx
Database.xlsx
Photo.jpg
```

Output:

```text
SecureFiles.policrypt
```

---

### 🧹 Clear

The **Clear** option removes the selected files and folders from the current encryption list.

It does not delete the original files from the computer.

---

### 🔓 Decrypt Container

The decryption interface is specifically designed for `.policrypt` containers.

1. Select **Decrypt**
2. Click **Load Container**
3. Select the `.policrypt` file
4. Enter the password
5. Select the destination directory
6. Click **Extract**

The application verifies the container before successful extraction.

---

### 📂 Select Extraction Directory

During decryption, the user must select where the encrypted files should be extracted.

Example:

```text
D:\Recovered\
```

The encrypted container itself is not modified.

---

### 🔑 Password Protection

The same password used during encryption must be provided during decryption.

If the password is incorrect, cryptographic authentication fails.

```text
Correct Password
      ↓
Successful Authentication
      ↓
Extraction

Wrong Password
      ↓
Authentication Failure
      ↓
No Successful Decryption
```

---

## 🌊 Streaming Encryption

PoliCrypt uses streaming processing instead of loading an entire file into RAM.

Large files are processed in smaller chunks.

Example:

```text
10 GB File
    ↓
Chunk 1
    ↓
Encrypt
    ↓
Write
    ↓
Chunk 2
    ↓
Encrypt
    ↓
Write
    ↓
...
    ↓
Final Chunk
```

This significantly reduces memory requirements when working with large files.

---

## 🆔 Container ID

Every PoliCrypt container receives a unique cryptographically random **Container ID**.

The Container ID provides unique identity and cryptographic context for the container.

Example:

```text
Container ID
    ↓
Unique Container Context
    ↓
Authenticated Container
```

The Container ID is not a password and cannot be used to decrypt the container.

---

## 🧂 Salt

Every container receives a randomly generated cryptographic salt.

The salt is used by Scrypt during password-based key derivation.

```text
Password + Salt
      ↓
Scrypt
      ↓
Master Key
```

The salt does not need to be secret and is stored in the container header.

---

## 🛡 Global Container Authentication

PoliCrypt uses a **global HMAC-SHA256 authentication mechanism** for the container.

The global MAC protects the integrity of the container structure and authenticated content.

```text
Container Header
      +
Encrypted Records
      +
END Record
      ↓
HMAC-SHA256
      ↓
Global Container MAC
```

If the container is modified, authentication should fail.

---

## 🔐 AES-256-GCM

PoliCrypt uses **AES-256-GCM** for authenticated encryption.

AES-256 provides strong symmetric encryption while GCM provides authentication of encrypted records.

Each encrypted data record contains authenticated cryptographic information.

```text
Plaintext
    ↓
AES-256-GCM
    ↓
Ciphertext + Authentication Tag
```

Any unauthorized modification to authenticated encrypted data should cause authentication failure.

---

## 🧬 HKDF-SHA256

HKDF-SHA256 is used for cryptographic key separation.

The Scrypt-derived master key is not directly reused for every cryptographic operation.

```text
Master Key
    ↓
HKDF-SHA256
    ↓
 ┌───────────────┐
 ↓               ↓
AES Key       HMAC Key
```

This separates encryption and authentication keys.

---

## 📦 Container Format

PoliCrypt encrypted files use the:

```text
.policrypt
```

extension.

A simplified container looks like:

```text
┌──────────────────────────────┐
│ Container Header             │
├──────────────────────────────┤
│ ENTRY                        │
├──────────────────────────────┤
│ DATA                         │
├──────────────────────────────┤
│ DATA                         │
├──────────────────────────────┤
│ DATA                         │
├──────────────────────────────┤
│ ENTRY                        │
├──────────────────────────────┤
│ DATA                         │
├──────────────────────────────┤
│ END                          │
├──────────────────────────────┤
│ Global HMAC-SHA256           │
└──────────────────────────────┘
```

---

## 📋 Container Records

### ENTRY

Contains authenticated information about a file or directory.

Example:

```text
Type
Path
Size
```

### DATA

Contains encrypted chunks of file contents.

### END

Indicates successful completion of the logical container stream.

### GLOBAL MAC

Provides final container-level authentication.

---

## 🔓 Decryption Verification

Before extraction, PoliCrypt validates the encrypted container.

```text
Load .policrypt
       ↓
Read Header
       ↓
Derive Keys
       ↓
Verify Global HMAC
       ↓
Verify Records
       ↓
Verify AES-GCM Authentication
       ↓
Verify END Record
       ↓
Extract
```

If any important authentication step fails:

```text
Authentication Failed
        ↓
Extraction Aborted
```

---

## 🛡 Path Traversal Protection

PoliCrypt validates paths before extracting files.

Unsafe paths such as:

```text
../../file.txt
```

or:

```text
C:\Windows\System32\file.dll
```

must not be accepted as valid extraction paths.

The extraction process is restricted to the selected destination directory.

---

## 💾 Original Files

Encrypting a file does not automatically delete the original plaintext file.

For example:

```text
Original:
D:\Documents\Secret.pdf

Encrypted:
D:\Encrypted\Secret.policrypt
```

The original file remains on the filesystem unless the user manually removes it.

Users should therefore understand that encryption does not equal secure deletion.

---

## 🔐 Password Recommendations

A strong password is essential.

Avoid:

```text
123456
password
admin
qwerty
12345678
```

Use a long and unique password or passphrase.

The security of the encrypted container ultimately depends on the secrecy and strength of the password.

---

## 🛡 Threat Model

### Protected Against

- Unauthorized access to encrypted containers
- Incorrect passwords
- Modified ciphertext
- Modified authentication tags
- Modified container records
- Container corruption detectable through authentication
- Record manipulation
- Record reordering
- Path traversal during extraction

### Not Protected Against

- Keyloggers
- Malware
- Compromised operating systems
- Memory attacks
- Screen capture
- Malicious software running with user privileges
- Password theft
- Weak or compromised passwords
- Plaintext files after extraction

---

## 💾 Backup Strategy

Always maintain backups of important `.policrypt` containers.

Recommended:

1. Primary encrypted container
2. Secondary backup
3. Offline backup

Example:

```text
SecureData.policrypt
        ↓
USB Backup
        ↓
Offline Backup
```

The password should not be stored together with the encrypted container.

---

## 🧪 Security Testing

The following tests should be performed:

| Test | Expected Result |
|------|-----------------|
| Correct password | Successful extraction |
| Wrong password | Authentication failure |
| Modified ciphertext | Authentication failure |
| Modified Container ID | Authentication failure |
| Modified salt | Authentication failure |
| Modified authentication tag | Authentication failure |
| Truncated container | Container failure |
| Missing END record | Container failure |
| Reordered records | Authentication failure |
| Invalid extraction path | Extraction rejected |
| Path traversal | Extraction rejected |

---

## 🧩 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| DECRYPT ERROR | Check the password and container integrity |
| Wrong password | Enter the original encryption password |
| Container not recognized | Make sure the selected file is a valid `.policrypt` container |
| Authentication failed | Container may be modified, corrupted, or password may be incorrect |
| Extraction failed | Check destination directory permissions |
| Folder not extracted | Verify container authentication and filesystem permissions |
| Large file processing | Allow the streaming operation to complete |
| Application not starting | Verify Python and required dependencies |
| Icon not showing | Verify `app.ico` exists in the application directory |

---

## 📁 Project Structure

```text
PoliCrypt/
│
├── app.py
├── app.ico
├── README.md
├── requirements.txt
└── LICENSE
```

---

## ⚙ Requirements

```text
Python 3.x
PyQt6
cryptography
```

Install dependencies:

```bash
pip install PyQt6 cryptography
```

Run:

```bash
python app.py
```

---

## 🪟 Windows EXE

PoliCrypt can be packaged into a standalone Windows executable using PyInstaller.

Install:

```bash
pip install pyinstaller
```

Build:

```bash
pyinstaller --onefile --windowed --icon=app.ico --name PoliCrypt app.py
```

The executable will be generated in:

```text
dist\PoliCrypt.exe
```

---

## 🖼 Application Icon

The application icon is stored as:

```text
app.ico
```

The recommended project structure is:

```text
PoliCrypt/
│
├── app.py
└── app.ico
```

---

## 📜 License

This project is released under the **GPLv3** license.

You may use, modify, and redistribute the project according to the terms of the GNU General Public License v3.

---

## 👤 Author

Created by **G.**

---

## 🔐 PoliCrypt – Privacy First, Local Encryption.

**AES-256-GCM • Scrypt • HKDF-SHA256 • HMAC-SHA256 • Streaming Containers**

---
