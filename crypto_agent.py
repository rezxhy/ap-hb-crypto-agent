#!/usr/bin/env python3
"""
AP-HB Crypto Agent — Agent de chiffrement automatique de fichiers sensibles
Conformité : RGPD, HIPAA, Loi chinoise sur la cybersécurité
Algorithme : AES-256-GCM (chiffrement authentifié) + PBKDF2-HMAC-SHA256 (dérivation de clé)

Usage:
    python3 crypto_agent.py keygen                        # Générer une clé maître
    python3 crypto_agent.py encrypt <dossier>             # Chiffrer un répertoire
    python3 crypto_agent.py decrypt <dossier> <dest>      # Déchiffrer un répertoire
    python3 crypto_agent.py watch <dossier>               # Surveiller et chiffrer en temps réel
    python3 crypto_agent.py status <dossier>              # Audit des fichiers
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
import secrets
import getpass
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─── Configuration ────────────────────────────────────────────────────────────

ENCRYPTED_EXT      = ".aphb"          # Extension des fichiers chiffrés
KEY_FILE           = "keys/master.key"
LOG_FILE           = "logs/crypto_agent.log"
EXCLUDED_EXTS      = {".aphb", ".py", ".key", ".log"}  # Ne pas re-chiffrer
PBKDF2_ITERATIONS  = 600_000          # NIST 2023 recommandation
AES_KEY_BITS       = 256
NONCE_SIZE         = 12               # 96 bits pour AES-GCM
SALT_SIZE          = 32               # 256 bits
MAGIC_HEADER       = b"APHB\x01"      # Signature d'en-tête

# ─── Logging ──────────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("APHBCryptoAgent")

# ─── Gestion des clés ─────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """Dérive une clé AES-256 depuis un mot de passe via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BITS // 8,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_master_key(key_path: str = KEY_FILE) -> None:
    """Génère et sauvegarde une clé maître protégée par mot de passe."""
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    print("\nGénération de la clé maître AP-HB")
    print("━" * 45)
    password = getpass.getpass("Mot de passe pour la clé maître : ")
    confirm  = getpass.getpass("Confirmer le mot de passe       : ")

    if password != confirm:
        log.error("Les mots de passe ne correspondent pas.")
        sys.exit(1)

    if len(password) < 12:
        log.error("Mot de passe trop court (minimum 12 caractères).")
        sys.exit(1)

    salt        = secrets.token_bytes(SALT_SIZE)
    raw_key     = secrets.token_bytes(AES_KEY_BITS // 8)   # clé aléatoire vraie
    derived_key = derive_key(password, salt)

    # Chiffre la clé brute avec la clé dérivée du mot de passe
    aesgcm = AESGCM(derived_key)
    nonce  = secrets.token_bytes(NONCE_SIZE)
    encrypted_raw_key = aesgcm.encrypt(nonce, raw_key, None)

    key_data = {
        "version"          : "1.0",
        "algorithm"        : "AES-256-GCM",
        "kdf"              : "PBKDF2-HMAC-SHA256",
        "iterations"       : PBKDF2_ITERATIONS,
        "salt_hex"         : salt.hex(),
        "nonce_hex"        : nonce.hex(),
        "encrypted_key_hex": encrypted_raw_key.hex(),
        "created_at"       : datetime.utcnow().isoformat() + "Z",
        "fingerprint"      : hashlib.sha256(raw_key).hexdigest()[:16],
    }

    with open(key_path, "w", encoding="utf-8") as f:
        json.dump(key_data, f, indent=2)

    os.chmod(key_path, 0o600)   # Lecture seule par le propriétaire
    log.info(f"Clé maître générée → {key_path}  (fingerprint: {key_data['fingerprint']})")
    print(f"\nClé sauvegardée dans '{key_path}'")
    print(f"   Empreinte : {key_data['fingerprint']}")
    print("Conservez votre mot de passe en lieu sûr. Sans lui, les données sont irrécupérables.\n")


def load_master_key(key_path: str = KEY_FILE, password: str | None = None) -> bytes:
    """Charge et déchiffre la clé maître depuis le fichier de clé."""
    if not os.path.exists(key_path):
        log.error(f"Fichier de clé introuvable : {key_path}")
        log.info("Exécutez d'abord :  python3 crypto_agent.py keygen")
        sys.exit(1)

    with open(key_path, "r", encoding="utf-8") as f:
        key_data = json.load(f)

    if password is None:
        password = getpass.getpass("Mot de passe de la clé maître : ")

    salt        = bytes.fromhex(key_data["salt_hex"])
    nonce       = bytes.fromhex(key_data["nonce_hex"])
    enc_key     = bytes.fromhex(key_data["encrypted_key_hex"])
    derived_key = derive_key(password, salt)

    try:
        aesgcm  = AESGCM(derived_key)
        raw_key = aesgcm.decrypt(nonce, enc_key, None)
    except InvalidTag:
        log.error("Mot de passe incorrect ou fichier de clé corrompu.")
        sys.exit(1)

    fp = hashlib.sha256(raw_key).hexdigest()[:16]
    log.info(f"Clé chargée (fingerprint: {fp})")
    return raw_key

# ─── Chiffrement / Déchiffrement de fichiers ─────────────────────────────────

def encrypt_file(src_path: str, key: bytes, delete_original: bool = True) -> str:
    """
    Chiffre un fichier avec AES-256-GCM.
    Format du fichier chiffré :
        MAGIC_HEADER (5 B) | nonce (12 B) | ciphertext+tag
    """
    dst_path = src_path + ENCRYPTED_EXT

    with open(src_path, "rb") as f:
        plaintext = f.read()

    nonce  = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)

    # L'AAD (Additional Authenticated Data) lie le nom du fichier au chiffré
    aad        = os.path.basename(src_path).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    with open(dst_path, "wb") as f:
        f.write(MAGIC_HEADER)
        f.write(nonce)
        f.write(ciphertext)

    if delete_original:
        # Écrasement sécurisé avant suppression (contre la récupération forensique)
        _secure_wipe(src_path)

    size_kb = len(plaintext) / 1024
    log.info(f"Chiffré : {src_path} → {dst_path}  ({size_kb:.1f} KB)")
    return dst_path


def decrypt_file(src_path: str, key: bytes, dest_dir: str | None = None) -> str:
    """Déchiffre un fichier .aphb et restaure l'original."""
    if not src_path.endswith(ENCRYPTED_EXT):
        raise ValueError(f"Extension inattendue (attendu {ENCRYPTED_EXT}) : {src_path}")

    with open(src_path, "rb") as f:
        data = f.read()

    if not data.startswith(MAGIC_HEADER):
        raise ValueError(f"En-tête invalide — fichier corrompu ou non-APHB : {src_path}")

    offset     = len(MAGIC_HEADER)
    nonce      = data[offset: offset + NONCE_SIZE]
    ciphertext = data[offset + NONCE_SIZE:]

    original_name = os.path.basename(src_path[: -len(ENCRYPTED_EXT)])
    aad           = original_name.encode("utf-8")

    try:
        aesgcm    = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        log.error(f"Intégrité compromise ou clé incorrecte : {src_path}")
        raise

    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)
        dst_path = os.path.join(dest_dir, original_name)
    else:
        dst_path = src_path[: -len(ENCRYPTED_EXT)]

    with open(dst_path, "wb") as f:
        f.write(plaintext)

    log.info(f"Déchiffré : {src_path} → {dst_path}")
    return dst_path


def _secure_wipe(path: str, passes: int = 3) -> None:
    """Écrase le fichier avec des données aléatoires avant suppression."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)

# ─── Opérations sur répertoires ───────────────────────────────────────────────

def encrypt_directory(directory: str, key: bytes) -> dict:
    """Chiffre récursivement tous les fichiers d'un répertoire."""
    stats = {"encrypted": 0, "skipped": 0, "errors": 0}
    path  = Path(directory)

    if not path.is_dir():
        log.error(f"Répertoire introuvable : {directory}")
        sys.exit(1)

    log.info(f"Chiffrement du répertoire : {directory}")

    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix in EXCLUDED_EXTS:
            stats["skipped"] += 1
            continue
        try:
            encrypt_file(str(file_path), key)
            stats["encrypted"] += 1
        except Exception as e:
            log.error(f"Erreur sur {file_path}: {e}")
            stats["errors"] += 1

    log.info(
        f"Chiffrement terminé — "
        f"chiffrés: {stats['encrypted']}, "
        f"ignorés: {stats['skipped']}, "
        f"erreurs: {stats['errors']}"
    )
    return stats


def decrypt_directory(directory: str, dest_dir: str, key: bytes) -> dict:
    """Déchiffre récursivement tous les fichiers .aphb d'un répertoire."""
    stats = {"decrypted": 0, "skipped": 0, "errors": 0}
    path  = Path(directory)

    log.info(f"Déchiffrement de : {directory} → {dest_dir}")

    for file_path in path.rglob(f"*{ENCRYPTED_EXT}"):
        if not file_path.is_file():
            continue
        try:
            decrypt_file(str(file_path), key, dest_dir)
            stats["decrypted"] += 1
        except Exception as e:
            log.error(f"Erreur sur {file_path}: {e}")
            stats["errors"] += 1

    log.info(
        f"Déchiffrement terminé — "
        f"déchiffrés: {stats['decrypted']}, "
        f"ignorés: {stats['skipped']}, "
        f"erreurs: {stats['errors']}"
    )
    return stats

# ─── Agent de surveillance temps réel ─────────────────────────────────────────

class EncryptionHandler(FileSystemEventHandler):
    """Surveille un répertoire et chiffre automatiquement tout nouveau fichier."""

    def __init__(self, key: bytes):
        super().__init__()
        self.key = key

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        ext  = Path(path).suffix
        if ext in EXCLUDED_EXTS:
            return
        # Attente courte pour s'assurer que l'écriture est terminée
        time.sleep(0.5)
        if os.path.exists(path):
            try:
                encrypt_file(path, self.key)
            except Exception as e:
                log.error(f"Auto-chiffrement échoué pour {path}: {e}")

    def on_modified(self, event):
        # Même logique sur modification
        self.on_created(event)


def watch_directory(directory: str, key: bytes) -> None:
    """Lance la surveillance en temps réel d'un répertoire."""
    handler  = EncryptionHandler(key)
    observer = Observer()
    observer.schedule(handler, directory, recursive=True)
    observer.start()

    log.info(f"Surveillance active : {directory}  (Ctrl+C pour arrêter)")
    print(f"\nSurveillance active sur '{directory}'")
    print("   Tout nouveau fichier sera chiffré automatiquement.")
    print("   Appuyez sur Ctrl+C pour arrêter.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log.info("Surveillance arrêtée.")

    observer.join()

# ─── Audit / Statut ───────────────────────────────────────────────────────────

def audit_directory(directory: str) -> None:
    """Affiche un rapport d'audit des fichiers dans le répertoire."""
    path      = Path(directory)
    encrypted = list(path.rglob(f"*{ENCRYPTED_EXT}"))
    plain     = [
        f for f in path.rglob("*")
        if f.is_file() and f.suffix not in EXCLUDED_EXTS
        and not f.suffix.endswith(ENCRYPTED_EXT)
    ]

    print(f"\n{'━'*50}")
    print(f"  RAPPORT D'AUDIT — {directory}")
    print(f"{'━'*50}")
    print(f"  Fichiers chiffrés (.aphb) : {len(encrypted)}")
    print(f"   Fichiers en clair         : {len(plain)}")

    if plain:
        print("\n  ATTENTION — Fichiers non protégés :")
        for f in plain[:20]:
            print(f"       • {f}")
        if len(plain) > 20:
            print(f"       … et {len(plain) - 20} autres.")

    total_size = sum(f.stat().st_size for f in encrypted) / (1024 * 1024)
    print(f"\n  Volume chiffré total : {total_size:.2f} MB")
    print(f"{'━'*50}\n")

# ─── Interface CLI ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AP-HB Crypto Agent — Chiffrement AES-256-GCM de fichiers de santé",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="Générer une clé maître")

    p_enc = sub.add_parser("encrypt", help="Chiffrer un répertoire")
    p_enc.add_argument("directory", help="Répertoire à chiffrer")

    p_dec = sub.add_parser("decrypt", help="Déchiffrer un répertoire")
    p_dec.add_argument("directory", help="Répertoire chiffré source")
    p_dec.add_argument("dest",      help="Répertoire de destination")

    p_wat = sub.add_parser("watch", help="Surveiller et chiffrer en temps réel")
    p_wat.add_argument("directory", help="Répertoire à surveiller")

    p_sta = sub.add_parser("status", help="Rapport d'audit d'un répertoire")
    p_sta.add_argument("directory", help="Répertoire à auditer")

    args = parser.parse_args()

    print("\n╔══════════════════════════════════════════╗")
    print("║  AP-HB Crypto Agent  •  AES-256-GCM     ║")
    print("║  Conformité RGPD / HIPAA / CSL Chine    ║")
    print("╚══════════════════════════════════════════╝\n")

    if args.command == "keygen":
        generate_master_key()

    elif args.command == "encrypt":
        key = load_master_key()
        encrypt_directory(args.directory, key)

    elif args.command == "decrypt":
        key = load_master_key()
        decrypt_directory(args.directory, args.dest, key)

    elif args.command == "watch":
        key = load_master_key()
        watch_directory(args.directory, key)

    elif args.command == "status":
        audit_directory(args.directory)


if __name__ == "__main__":
    main()
