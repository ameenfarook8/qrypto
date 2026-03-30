#!/usr/bin/env python3

import json
import os
import base64
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
from urllib.parse import urlparse, parse_qs, unquote

# --- Dependency check ---
try:
    import cv2
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import qrcode
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("\nInstall with:")
    print("  pip install opencv-python cryptography qrcode[pil] typer rich keyring")
    raise SystemExit(1)


app = typer.Typer(
    help=(
        "QR Crypto — scan, encrypt, and regenerate QR codes securely.\n\n"
        "Auth modes (use one per command):\n\n"
        "  [default]   macOS Keychain (recommended)\n\n"
        "  --password  Derives key from a memorable passphrase\n\n"
        "  --keyfile   Uses a key file (looks for qr.key in current dir, prompts if missing)\n\n"
        "Examples:\n\n"
        "  qrypto scan my.png aws-prod\n\n"
        "  qrypto scan my.png aws-prod --password 'my phrase'\n\n"
        "  qrypto scan my.png aws-prod --keyfile\n\n"
        "  qrypto regen aws-prod\n\n"
        "  qrypto show aws-prod\n\n"
        "  qrypto list\n\n"
        "  qrypto ui\n\n"
        "  qrypto ui --background\n\n"
        "  qrypto ui --stop"
    ),
    pretty_exceptions_show_locals=False,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
)
console = Console()

SALT = b"qr-crypto-salt-v1"
KEYCHAIN_SERVICE = "qr-crypto"
KEYCHAIN_ACCOUNT = "main"


def resolve_qrypto_dir() -> Path:
    """Return the .qrypto dir to use — cwd if initialised, else home fallback."""
    local = Path.cwd() / ".qrypto"
    if local.exists():
        return local
    return Path.home() / ".qrypto"


def get_paths():
    d = resolve_qrypto_dir()
    return d, d / "qr.key", d / "qr_store.json", d / "qr_store.md"


AUTH_COLORS = {
    "keychain": "cyan",
    "password": "yellow",
    "key-file": "green",
}


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------

def key_from_file(key_file: Optional[str] = None) -> bytes:
    _, default_key_file, _, _ = get_paths()
    # If no path given, check .qrypto dir first
    if key_file is None:
        if default_key_file.exists():
            key_file = str(default_key_file)
        else:
            console.print(f"  [yellow]No qr.key found in .qrypto/[/yellow]")
            key_file = typer.prompt("  Enter path to key file (or press Enter to generate one here)", default=str(default_key_file))

    path = Path(key_file)
    if path.exists():
        key = path.read_bytes()
        console.print(f"  [dim]Loaded key from '{key_file}'[/dim]")
    else:
        key = Fernet.generate_key()
        path.write_bytes(key)
        console.print(f"  [green]Generated new key → saved to '{key_file}'[/green]")
        console.print(f"  [bold red]Keep this file safe — needed to regenerate QR codes.[/bold red]")
    return key


def key_from_password(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def key_from_keychain() -> bytes:
    try:
        import keyring
    except ImportError:
        console.print("[bold red]keyring not installed.[/bold red] Run: pip install keyring")
        raise typer.Exit(1)

    raw = keyring.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    if raw:
        console.print("  [dim]Loaded key from macOS Keychain[/dim]")
        return raw.encode()
    else:
        key = Fernet.generate_key()
        keyring.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key.decode())
        console.print("  [green]Generated new key → stored in macOS Keychain[/green]")
        return key


def resolve_key(
    password: Optional[str],
    use_keyfile: bool,
) -> bytes:
    if password and use_keyfile:
        console.print("[bold red]Use either --password or --keyfile, not both.[/bold red]")
        raise typer.Exit(1)
    if use_keyfile:
        return key_from_file()
    if password:
        console.print("  [dim]Using password-derived key[/dim]")
        return key_from_password(password)
    # default: keychain
    return key_from_keychain()


def detect_auth(password: Optional[str], use_keyfile: bool) -> str:
    if use_keyfile:
        return "key-file"
    if password:
        return "password"
    return "keychain"


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def load_store() -> dict:
    _, _, store_json, _ = get_paths()
    if store_json.exists():
        return json.loads(store_json.read_text(encoding="utf-8"))
    return {}


def save_store(store: dict):
    qrypto_dir, _, store_json, _ = get_paths()
    qrypto_dir.mkdir(exist_ok=True)
    store_json.write_text(json.dumps(store, indent=2), encoding="utf-8")
    _write_md(store)


def _write_md(store: dict):
    lines = [
        "# QR Code Store\n",
        "| Name | QR Type | Issuer | Account | Added | Auth |",
        "|------|---------|--------|---------|-------|------|",
    ]
    for name, entry in store.items():
        auth = entry.get("auth", "keychain")
        qr_type = entry.get("qr_type", "—")
        issuer = entry.get("issuer", "—")
        account = entry.get("account", "—")
        lines.append(f"| `{name}` | {qr_type} | {issuer} | {account} | {entry['added']} | `{auth}` |")
    lines.append("")
    _, _, _, store_md = get_paths()
    store_md.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# OTP URI parsing
# ---------------------------------------------------------------------------

def detect_qr_meta(data: str) -> Dict[str, str]:
    """
    Detect QR code type and extract safe metadata.
    Never includes the secret for otpauth URIs.
    """
    # 2FA QR code
    if data.startswith("otpauth://"):
        parsed = urlparse(data)
        otp_type = parsed.netloc  # totp or hotp
        params = parse_qs(parsed.query)
        label = unquote(parsed.path.lstrip("/"))
        if ":" in label:
            label_issuer, account = label.split(":", 1)
        else:
            label_issuer, account = "", label
        issuer = params.get("issuer", [label_issuer or "Unknown"])[0]
        return {
            "qr_type": "2FA",
            "otp_type": otp_type.upper(),
            "issuer": issuer,
            "account": account.strip(),
        }

    # URL
    if data.startswith("http://") or data.startswith("https://"):
        parsed = urlparse(data)
        return {
            "qr_type": "URL",
            "otp_type": "—",
            "issuer": parsed.netloc,
            "account": "—",
        }

    # WiFi — format: WIFI:S:<ssid>;T:<type>;P:<password>;;
    if data.startswith("WIFI:"):
        ssid = ""
        for part in data[5:].split(";"):
            if part.startswith("S:"):
                ssid = part[2:]
        return {
            "qr_type": "WiFi",
            "otp_type": "—",
            "issuer": "—",
            "account": ssid or "—",
        }

    # Generic / plain text
    return {
        "qr_type": "Generic",
        "otp_type": "—",
        "issuer": "—",
        "account": "—",
    }


# ---------------------------------------------------------------------------
# App callback + init command
# ---------------------------------------------------------------------------

@app.callback()
def _callback(ctx: typer.Context):
    if ctx.invoked_subcommand and ctx.invoked_subcommand != "init":
        d = resolve_qrypto_dir()
        if not d.exists():
            console.print(f"[dim]no local .qrypto found, using {d}[/dim]")
        else:
            console.print(f"[dim]store: {d}[/dim]")


@app.command()
def init():
    """Initialise a .qrypto store in the current directory."""
    local = Path.cwd() / ".qrypto"
    if local.exists():
        console.print(f"[yellow]Already initialised.[/yellow] Store exists at [dim]{local}[/dim]")
        return
    local.mkdir()
    console.print(Panel(
        f"[bold green]Initialised[/bold green] store at [cyan]{local}[/cyan]\n\n"
        f"All qrypto data for this directory will be stored here.\n"
        f"Run commands from [dim]{Path.cwd()}[/dim] to use this store.",
        title="[bold green]qrypto init[/bold green]",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def scan_qr(image_path: str) -> str:
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Could not open image: {image_path}")
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    if not data:
        raise ValueError("No QR code detected in the image.")
    return data


def encrypt(data: str, key: bytes) -> str:
    return Fernet(key).encrypt(data.encode()).decode()


def decrypt(token: str, key: bytes) -> str:
    return Fernet(key).decrypt(token.encode()).decode()


def make_qr(data: str, output_path: str):
    qrcode.make(data).save(output_path)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command(
    epilog=(
        "Examples:\n\n"
        "  qrypto scan my.png aws-prod\n\n"
        "  qrypto scan my.png aws-prod --password 'my phrase'\n\n"
        "  qrypto scan my.png aws-prod --keyfile"
    )
)
def scan(
    image: str = typer.Argument(..., help="Path to the QR code image"),
    name: str = typer.Argument(..., help="Readable name to store it under, e.g. aws-prod"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Derive key from a memorable passphrase"),
    keyfile: bool = typer.Option(False, "--keyfile", "-f", help="Use a key file instead of Keychain"),
):
    """Scan a QR code image and store it encrypted. Defaults to macOS Keychain."""
    store = load_store()
    if name in store:
        console.print(f"[bold red]Name '{name}' already exists.[/bold red] Use a different name or remove it first.")
        raise typer.Exit(1)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
        progress.add_task("Resolving key...", total=None)
        key = resolve_key(password, keyfile)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
        progress.add_task("Scanning QR code...", total=None)
        try:
            data = scan_qr(image)
        except ValueError as e:
            console.print(f"[bold red]{e}[/bold red]")
            raise typer.Exit(1)

    meta = detect_qr_meta(data)

    token = encrypt(data, key)
    store[name] = {
        "token": token,
        "added": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "auth": detect_auth(password, keyfile),
        "qr_type": meta["qr_type"],
        "otp_type": meta["otp_type"],
        "issuer": meta["issuer"],
        "account": meta["account"],
    }
    save_store(store)

    panel_lines = (
        f"[bold green]Saved[/bold green] [cyan]{name}[/cyan]\n"
        f"[dim]QR Type:[/dim]  {meta['qr_type']}\n"
    )
    if meta["qr_type"] == "2FA":
        panel_lines += (
            f"[dim]Issuer:[/dim]   {meta['issuer']}\n"
            f"[dim]Account:[/dim]  {meta['account']}\n"
            f"[dim]OTP Type:[/dim] {meta['otp_type']}\n"
        )
    elif meta["qr_type"] == "URL":
        panel_lines += f"[dim]Domain:[/dim]   {meta['issuer']}\n"
    elif meta["qr_type"] == "WiFi":
        panel_lines += f"[dim]SSID:[/dim]     {meta['account']}\n"

    panel_lines += (
        f"[dim]Auth:[/dim]     {store[name]['auth']}\n\n"
        f"Regenerate with: [bold]qrypto regen {name}[/bold]"
    )

    console.print(Panel(
        panel_lines,
        title="[bold green]QR Encrypted[/bold green]",
        border_style="green",
    ))


@app.command(
    epilog=(
        "Examples:\n\n"
        "  qrypto regen aws-prod\n\n"
        "  qrypto regen aws-prod --password 'my phrase'\n\n"
        "  qrypto regen aws-prod --keyfile"
    )
)
def regen(
    name: str = typer.Argument(..., help="Name of the stored entry"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Passphrase used during scan"),
    keyfile: bool = typer.Option(False, "--keyfile", "-f", help="Use a key file instead of Keychain"),
):
    """Decrypt a stored entry and regenerate its QR code image. Defaults to macOS Keychain."""
    store = load_store()
    if name not in store:
        console.print(f"[bold red]No entry found for '{name}'.[/bold red] Run [cyan]list[/cyan] to see all entries.")
        raise typer.Exit(1)

    stored_auth = store[name].get("auth", "keychain")
    used_auth = detect_auth(password, keyfile)
    if used_auth != stored_auth:
        hint = {
            "keychain": f"qrypto regen {name}",
            "password": f"qrypto regen {name} --password <your-password>",
            "key-file": f"qrypto regen {name} --keyfile",
        }.get(stored_auth, "")
        console.print(
            f"[bold red]Wrong auth method.[/bold red] "
            f"'{name}' was encrypted with [cyan]{stored_auth}[/cyan], "
            f"but you used [yellow]{used_auth}[/yellow].\n"
            f"[dim]Try:[/dim] [bold]{hint}[/bold]"
        )
        raise typer.Exit(1)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
        progress.add_task("Resolving key...", total=None)
        key = resolve_key(password, keyfile)

    try:
        data = decrypt(store[name]["token"], key)
    except Exception:
        console.print("[bold red]Decryption failed.[/bold red] Wrong password or key.")
        raise typer.Exit(1)

    output = f"{name}_qr.png"
    make_qr(data, output)

    console.print(Panel(
        f"[bold green]Regenerated[/bold green] [cyan]{name}[/cyan]\n"
        f"[dim]Data:[/dim]   {data!r}\n"
        f"[dim]Saved:[/dim]  {output}",
        title="[bold green]QR Regenerated[/bold green]",
        border_style="green",
    ))


@app.command()
def show(
    name: str = typer.Argument(..., help="Name of the stored entry"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Passphrase used during scan"),
    keyfile: bool = typer.Option(False, "--keyfile", "-f", help="Use a key file instead of Keychain"),
):
    """Decrypt a stored entry and display its QR code in the terminal."""
    store = load_store()
    if name not in store:
        console.print(f"[bold red]No entry found for '{name}'.[/bold red] Run [cyan]list[/cyan] to see all entries.")
        raise typer.Exit(1)

    stored_auth = store[name].get("auth", "keychain")
    used_auth = detect_auth(password, keyfile)
    if used_auth != stored_auth:
        hint = {
            "keychain": f"qrypto show {name}",
            "password": f"qrypto show {name} --password <your-password>",
            "key-file": f"qrypto show {name} --keyfile",
        }.get(stored_auth, "")
        console.print(
            f"[bold red]Wrong auth method.[/bold red] "
            f"'{name}' was encrypted with [cyan]{stored_auth}[/cyan], "
            f"but you used [yellow]{used_auth}[/yellow].\n"
            f"[dim]Try:[/dim] [bold]{hint}[/bold]"
        )
        raise typer.Exit(1)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
        progress.add_task("Resolving key...", total=None)
        key = resolve_key(password, keyfile)

    try:
        data = decrypt(store[name]["token"], key)
    except Exception:
        console.print("[bold red]Decryption failed.[/bold red] Wrong password or key.")
        raise typer.Exit(1)

    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.make(fit=True)

    console.print(f"\n[bold cyan]{name}[/bold cyan]")
    qr.print_ascii(invert=True)
    console.print()


@app.command(
    epilog=(
        "Examples:\n\n"
        "  # rotate all — keychain → new password\n"
        "  qrypto rotate --new-password 'new phrase'\n\n"
        "  # rotate all — password → keychain\n"
        "  qrypto rotate --old-password 'old phrase'\n\n"
        "  # rotate all — password → new password\n"
        "  qrypto rotate --old-password 'old' --new-password 'new'\n\n"
        "  # rotate all — keyfile → keychain\n"
        "  qrypto rotate --keyfile-old\n\n"
        "  # rotate single entry only\n"
        "  qrypto rotate --name aws-prod --old-password 'old' --new-password 'new'\n\n"
        "  # rotate single entry — keychain → keyfile\n"
        "  qrypto rotate --name github --keyfile-new"
    )
)
def rotate(
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Rotate a single entry by name. Omit to rotate all."),
    old_password: Optional[str] = typer.Option(None, "--old-password", help="Current passphrase (if password auth)"),
    new_password: Optional[str] = typer.Option(None, "--new-password", help="New passphrase to rotate to"),
    keyfile_old: bool = typer.Option(False, "--keyfile-old", help="Current auth is key file"),
    keyfile_new: bool = typer.Option(False, "--keyfile-new", help="New auth should use key file"),
):
    """Re-encrypt tokens with a new key or password. Rotates all entries unless --name is given."""
    store = load_store()
    if not store:
        console.print("[yellow]No entries to rotate.[/yellow]")
        return

    if name and name not in store:
        console.print(f"[bold red]No entry found for '{name}'.[/bold red] Run [cyan]list[/cyan] to see all entries.")
        raise typer.Exit(1)

    targets = {name: store[name]} if name else store

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as progress:
        progress.add_task("Resolving keys...", total=None)
        old_key = resolve_key(old_password, keyfile_old)
        new_key = resolve_key(new_password, keyfile_new)

    new_auth = detect_auth(new_password, keyfile_new)
    rotated = 0

    for entry_name, entry in targets.items():
        try:
            data = decrypt(entry["token"], old_key)
            entry["token"] = encrypt(data, new_key)
            entry["auth"] = new_auth
            rotated += 1
        except Exception:
            console.print(f"  [red]Failed to re-encrypt '{entry_name}' — skipping.[/red]")

    save_store(store)
    scope = f"[cyan]{name}[/cyan]" if name else f"[bold]{rotated}/{len(store)} entries[/bold]"
    console.print(Panel(
        f"[bold green]Rotated[/bold green] {scope}\n"
        f"[dim]New auth method:[/dim] {new_auth}",
        title="[bold green]Rotation Complete[/bold green]",
        border_style="green",
    ))


@app.command(name="list")
def list_entries():
    """List all stored QR entries."""
    store = load_store()
    if not store:
        console.print("[yellow]No entries yet.[/yellow] Use [cyan]scan[/cyan] to add one.")
        return

    table = Table(box=box.ROUNDED, border_style="dim", show_lines=False)
    table.add_column("Name", style="cyan bold", no_wrap=True)
    table.add_column("QR Type", justify="center")
    table.add_column("Issuer")
    table.add_column("Account", style="dim")
    table.add_column("Added", style="dim")
    table.add_column("Auth", justify="center")

    for name, entry in store.items():
        auth = entry.get("auth", "keychain")
        color = AUTH_COLORS.get(auth, "white")
        qr_type = entry.get("qr_type", "—")
        qr_color = {"2FA": "green", "URL": "blue", "WiFi": "yellow", "Generic": "dim"}.get(qr_type, "white")
        table.add_row(
            name,
            f"[{qr_color}]{qr_type}[/{qr_color}]",
            entry.get("issuer", "—"),
            entry.get("account", "—"),
            entry["added"],
            f"[{color}]{auth}[/{color}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------

def _pid_file() -> Path:
    return resolve_qrypto_dir() / "ui.pid"


@app.command()
def ui(
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    background: bool = typer.Option(False, "--background", "-b", help="Run server in background"),
    stop: bool = typer.Option(False, "--stop", help="Stop a background server"),
):
    """Start the web UI in your browser."""
    import signal

    if stop:
        pid_path = _pid_file()
        if not pid_path.exists():
            console.print("[yellow]No background server found.[/yellow]")
            raise typer.Exit(0)
        pid = int(pid_path.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            pid_path.unlink()
            console.print(f"[bold green]Stopped[/bold green] Qrypto UI (pid {pid})")
        except ProcessLookupError:
            pid_path.unlink(missing_ok=True)
            console.print("[yellow]Server was not running (stale pid file removed).[/yellow]")
        raise typer.Exit(0)

    try:
        import uvicorn
        from server import app as fastapi_app
    except ImportError as e:
        console.print(f"[bold red]Missing dependency:[/bold red] {e}")
        console.print("Install with: [cyan]pip install fastapi uvicorn[standard] python-multipart[/cyan]")
        raise typer.Exit(1)

    url = f"http://{host}:{port}"

    if background:
        import subprocess, sys
        pid_path = _pid_file()
        if pid_path.exists():
            existing = pid_path.read_text().strip()
            console.print(f"[yellow]Server already running (pid {existing}).[/yellow] Use [cyan]qrypto ui --stop[/cyan] first.")
            raise typer.Exit(1)
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server:app", "--host", host, "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid_path.write_text(str(proc.pid))
        console.print(Panel(
            f"[bold green]Qrypto UI[/bold green] running in background → [cyan]{url}[/cyan]\n\n"
            f"[dim]pid {proc.pid} · stop with:[/dim] [bold]qrypto ui --stop[/bold]",
            border_style="green",
        ))
        return

    console.print(Panel(
        f"[bold green]Qrypto UI[/bold green] → [cyan]{url}[/cyan]\n\n"
        f"[dim]Press Ctrl+C to stop[/dim]",
        border_style="green",
    ))
    uvicorn.run(fastapi_app, host=host, port=port)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
