# Qrypto

Scan a QR code from an image, encrypt its data, and store it under a readable name. Regenerate the QR code later using just that name.

Designed for securely storing 2FA QR codes — scan once, delete the image, regenerate when needed.

## Install

Requires Python 3.9+ and [pipx](https://pipx.pypa.io).

### Don't have Python?

**macOS:**

```bash
brew install python
```

> Don't have Homebrew? Install it from [brew.sh](https://brew.sh)

**Windows:**
Download the installer from [python.org/downloads](https://www.python.org/downloads) and run it.
Make sure to check **"Add Python to PATH"** during installation.

**Linux (Ubuntu/Debian):**

```bash
sudo apt update && sudo apt install python3 python3-pip
```

### Don't have pipx?

Once Python is installed:

```bash
pip install pipx
pipx ensurepath
```

Then restart your terminal.

---

**Latest version (tracks `main` branch):**

```bash
pipx install git+https://github.com/ameenfarook8/qrypto.git
```

**Specific release (stable, pinned):**

```bash
pipx install git+https://github.com/ameenfarook8/qrypto.git@v1.0.1
```

**Upgrade to latest:**

```bash
pipx upgrade qrypto
```

> Note: if you installed a specific tag (`@v1.0.1`), upgrade won't move to a newer tag — uninstall and reinstall with the new version instead.

### Uninstall

```bash
pipx uninstall qrypto
```

## Run from source (no install)

If you prefer to clone and run directly without installing:

```bash
# 1. Clone the repo
git clone https://github.com/ameenfarook8/qrypto.git
cd qrypto

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run directly
python qrypto.py --help
python qrypto.py scan my.png aws-prod
python qrypto.py list
```

> To deactivate the virtual environment when done: `deactivate`

To get updates later:

```bash
git pull
pip install -r requirements.txt  # in case dependencies changed
```

---

## Setup

After installing, navigate to the folder you want to use as your store and initialise it:

```bash
cd ~/my-secure-folder
qrypto init
```

Then use `qrypto` from that folder:

```bash
qrypto scan my.png aws-prod
qrypto regen aws-prod
qrypto show aws-prod
qrypto list
```

> If you haven't run `qrypto init`, commands fall back to `~/.qrypto` in your home directory automatically.

## Auth modes

| Flag                  | Mechanism                                              | Default? |
| --------------------- | ------------------------------------------------------ | -------- |
| _(none)_              | macOS Keychain (Touch ID protected)                    | **Yes**  |
| `--password <phrase>` | PBKDF2 key derived from passphrase                     | No       |
| `--keyfile`           | Key file (`qr.key` in current dir, prompts if missing) | No       |

## Usage

### Scan & encrypt a QR code

```bash
qrypto scan <image_path> <name> [--password <phrase> | --keyfile]
```

```bash
qrypto scan my_qr.png aws-prod              # keychain (default)
qrypto scan my_qr.png aws-prod --password "my phrase"
qrypto scan my_qr.png aws-prod --keyfile
```

### Regenerate QR from name

```bash
qrypto regen <name> [--password <phrase> | --keyfile]
```

```bash
qrypto regen aws-prod                       # keychain (default)
qrypto regen aws-prod --password "my phrase"
qrypto regen aws-prod --keyfile
```

Saves QR as `aws-prod_qr.png`. Use the same auth mode as `scan`.

### Show QR code in terminal

```bash
qrypto show <name> [--password <phrase> | --keyfile]
```

```bash
qrypto show aws-prod                        # keychain (default)
qrypto show aws-prod --password "my phrase"
qrypto show aws-prod --keyfile
```

Decrypts the stored entry and renders the QR code directly in your terminal using Unicode block characters. Use the same auth mode as `scan`.

### Rotate to a new key

Rotates **all** entries by default. Add `--name` to target a single one.

```bash
# rotate all — keychain → new password
qrypto rotate --new-password "new phrase"

# rotate all — password → keychain
qrypto rotate --old-password "old phrase"

# rotate all — password → new password
qrypto rotate --old-password "old" --new-password "new"

# rotate all — keyfile → keychain
qrypto rotate --keyfile-old

# rotate single entry only
qrypto rotate --name aws-prod --old-password "old" --new-password "new"

# rotate single entry — keychain → keyfile
qrypto rotate --name github --keyfile-new
```

### List all stored entries

```bash
qrypto list
```

## Supported QR code types

Any QR code can be encrypted and stored. The tool auto-detects the type and stores safe metadata:

| Type      | Detection              | Metadata stored                                                                  |
| --------- | ---------------------- | -------------------------------------------------------------------------------- |
| `2FA`     | `otpauth://` URI       | issuer, account, OTP type — **secret encrypted only, never stored in plaintext** |
| `URL`     | `http://` / `https://` | domain                                                                           |
| `WiFi`    | `WIFI:` prefix         | SSID                                                                             |
| `Generic` | anything else          | —                                                                                |

## Output files

All data files are stored in `.qrypto/` — created by `qrypto init` in the current directory, or falls back to `~/.qrypto/` if not initialised. Every command prints the active store path in dim text so you always know which store is being used.

| File                    | Purpose                                                       |
| ----------------------- | ------------------------------------------------------------- |
| `.qrypto/qr.key`        | Key file (only when using `--keyfile`)                        |
| `.qrypto/qr_store.json` | Entries: name, issuer, account, type, auth, date — no secrets |
| `.qrypto/qr_store.md`   | Same content as a readable markdown table                     |
| `<name>_qr.png`         | Regenerated QR code image (written to current directory)      |

## How it works

1. OpenCV reads the QR code data from the image
2. QR type is auto-detected (2FA, URL, WiFi, Generic) and safe metadata is extracted
3. For 2FA codes, issuer/account/OTP type are parsed — secret stays untouched in memory
4. Key is resolved — from Keychain (default), PBKDF2 password derivation, or a key file
5. Full QR data (including any secrets) is encrypted with `cryptography.Fernet` (AES-128-CBC + HMAC-SHA256)
6. Safe metadata + encrypted token saved to JSON/MD — secrets never written in plaintext
7. On regen, auth method is checked first — clear error if wrong mode used
8. Token decrypted, QR image rebuilt from the original data
