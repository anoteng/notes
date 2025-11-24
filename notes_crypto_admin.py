#!/usr/bin/env python3
"""
Admin-skript for kryptering i notes-systemet.

Funksjoner:
- enroll: opprett dek_for_recovery for en bruker (krever brukerpassord + recovery-nøkkel)
- recover: sett nytt krypteringspassord for en bruker (krever recovery-nøkkel)

Bruk:
  python3 notes_crypto_admin.py enroll
  python3 notes_crypto_admin.py recover
"""

import os
import sys
import getpass
import hashlib
import pymysql
from typing import Tuple, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Du må installere cryptography først, f.eks.:")
    print("  pip install cryptography")
    sys.exit(1)

# ---- KONFIGURASJON ----
# Tilpass disse til ditt miljø

DB_HOST = os.getenv("NOTES_DB_HOST", "127.0.0.1")
DB_USER = os.getenv("NOTES_DB_USER", "notes")
DB_PASS = os.getenv("NOTES_DB_PASS", "")  # sett ev. i shell
DB_NAME = os.getenv("NOTES_DB_NAME", "notes")

# PBKDF2-parametre må matche frontend (crypto.js)
PBKDF2_ITERATIONS = 200_000
PBKDF2_HASH_NAME = "sha256"

# Vi bruker SHA-256(recovery_key) som AES-GCM-nøkkel (32 byte).
# Recovery-nøkkelen skrives aldri til DB.
# ------------------------


def db_connect():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        charset="utf8mb4",
        autocommit=True,
    )


def derive_kek_from_password(password: str, salt: bytes) -> bytes:
    """
    Deriverer KEK (32 byte) fra passord + salt ved PBKDF2.
    Må matche det som skjer i browseren (WebCrypto).
    """
    pwd_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH_NAME,
        pwd_bytes,
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def derive_recovery_aes_key(recovery_key: str) -> bytes:
    """
    Gjør recovery-nøkkelen om til 32-byte AES-nøkkel ved SHA-256.
    """
    return hashlib.sha256(recovery_key.encode("utf-8")).digest()


def decrypt_dek_for_user(dek_for_user: bytes, kek: bytes) -> bytes:
    """
    dek_for_user = iv(12) || ciphertext+tag
    AES-GCM med KEK.
    """
    if dek_for_user is None:
        raise ValueError("dek_for_user er NULL i databasen.")

    if len(dek_for_user) <= 12:
        raise ValueError("dek_for_user er for kort til å inneholde iv + ciphertext.")

    iv = dek_for_user[:12]
    ct = dek_for_user[12:]

    aesgcm = AESGCM(kek)
    dek = aesgcm.decrypt(iv, ct, None)  # -> raw DEK (32 byte)
    return dek


def encrypt_dek_for_user(dek: bytes, kek: bytes) -> bytes:
    """
    Krypter DEK med KEK som i frontend:
    lagrer iv(12) || ciphertext+tag
    """
    if len(dek) != 32:
        raise ValueError("Forventer 32 byte DEK, fikk %d byte" % len(dek))

    iv = os.urandom(12)
    aesgcm = AESGCM(kek)
    ct = aesgcm.encrypt(iv, dek, None)
    return iv + ct


def encrypt_dek_for_recovery(dek: bytes, recovery_aes_key: bytes) -> bytes:
    """
    Krypter DEK med recovery-nøkkelen (AES-GCM, iv || ciphertext+tag).
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(recovery_aes_key)
    ct = aesgcm.encrypt(iv, dek, None)
    return iv + ct


def decrypt_dek_for_recovery(dek_for_recovery: bytes, recovery_aes_key: bytes) -> bytes:
    """
    Dekrypter dek_for_recovery for å hente DEK.
    """
    if dek_for_recovery is None:
        raise ValueError("dek_for_recovery er NULL i databasen (bruker ikke enroll'et).")

    if len(dek_for_recovery) <= 12:
        raise ValueError("dek_for_recovery er for kort til å inneholde iv + ciphertext.")

    iv = dek_for_recovery[:12]
    ct = dek_for_recovery[12:]

    aesgcm = AESGCM(recovery_aes_key)
    dek = aesgcm.decrypt(iv, ct, None)
    return dek


def get_user_row_by_email(conn, email: str) -> Optional[Tuple]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, name, email, crypto_salt, dek_for_user, dek_for_recovery
            FROM users
            WHERE email=%s
            """,
            (email,),
        )
        row = cur.fetchone()
    return row


def enroll_user():
    """
    Opprett dek_for_recovery for én bruker.

    Krever:
      - recovery-nøkkel
      - brukerens e-post
      - brukerens nåværende krypteringspassord
    """
    print("=== ENROLL USER (opprette dek_for_recovery) ===")

    recovery_key = getpass.getpass("Recovery-nøkkel (skjult): ")
    if not recovery_key:
        print("Avbrutt: ingen recovery-nøkkel oppgitt.")
        return

    email = input("Brukerens e-post: ").strip()
    if not email:
        print("Avbrutt: ingen e-post.")
        return

    user_password = getpass.getpass("Brukerens krypteringspassord (skjult): ")
    if not user_password:
        print("Avbrutt: ingen passord.")
        return

    conn = db_connect()
    try:
        row = get_user_row_by_email(conn, email)
        if not row:
            print(f"Fant ingen bruker med e-post {email}")
            return

        user_id, name, email_db, crypto_salt, dek_for_user, dek_for_recovery = row
        if crypto_salt is None or dek_for_user is None:
            print("Brukeren har ikke satt opp kryptering (crypto_salt eller dek_for_user er NULL).")
            return

        print(f"Fant bruker id={user_id}, navn={name}")

        if dek_for_recovery is not None:
            ans = input("Brukeren har allerede dek_for_recovery. Overskrive? [y/N]: ").strip().lower()
            if ans != "y":
                print("Avbrutt, ingen endring.")
                return

        # 1) Deriver KEK fra brukerpassord
        kek = derive_kek_from_password(user_password, crypto_salt)

        # 2) Dekrypter dek_for_user -> DEK
        dek = decrypt_dek_for_user(dek_for_user, kek)
        print("DEK dekryptert OK.")

        # 3) Deriver recovery-AES-nøkkel
        recovery_aes_key = derive_recovery_aes_key(recovery_key)

        # 4) Krypter DEK for recovery
        dek_for_recovery_new = encrypt_dek_for_recovery(dek, recovery_aes_key)

        # 5) Skriv til DB
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET dek_for_recovery=%s WHERE id=%s",
                (dek_for_recovery_new, user_id),
            )

        print("dek_for_recovery oppdatert for bruker", email_db)

    finally:
        conn.close()


def recover_user():
    """
    Sett nytt krypteringspassord for en bruker ved hjelp av recovery-nøkkelen.

    Krever:
      - recovery-nøkkel
      - brukerens e-post
      - nytt krypteringspassord
    """
    print("=== RECOVER USER (sette nytt krypteringspassord) ===")

    recovery_key = getpass.getpass("Recovery-nøkkel (skjult): ")
    if not recovery_key:
        print("Avbrutt: ingen recovery-nøkkel oppgitt.")
        return

    email = input("Brukerens e-post: ").strip()
    if not email:
        print("Avbrutt: ingen e-post.")
        return

    new_password = getpass.getpass("Nytt krypteringspassord (skjult): ")
    new_password2 = getpass.getpass("Gjenta nytt passord: ")
    if new_password != new_password2:
        print("Passordene er ikke like. Avbrutt.")
        return
    if not new_password:
        print("Avbrutt: tomt passord.")
        return

    conn = db_connect()
    try:
        row = get_user_row_by_email(conn, email)
        if not row:
            print(f"Fant ingen bruker med e-post {email}")
            return

        user_id, name, email_db, crypto_salt, dek_for_user, dek_for_recovery = row
        if crypto_salt is None:
            print("Brukeren har ikke crypto_salt satt (har aldri brukt kryptering?).")
            return

        if dek_for_recovery is None:
            print("Brukeren har ingen dek_for_recovery. Må enroll'es først.")
            return

        print(f"Fant bruker id={user_id}, navn={name}")

        # 1) Deriver recovery-AES-nøkkel
        recovery_aes_key = derive_recovery_aes_key(recovery_key)

        # 2) Dekrypter dek_for_recovery -> DEK
        dek = decrypt_dek_for_recovery(dek_for_recovery, recovery_aes_key)
        print("DEK dekryptert fra dek_for_recovery OK.")

        # 3) Deriver ny KEK fra nytt passord
        kek_new = derive_kek_from_password(new_password, crypto_salt)

        # 4) Krypter DEK på nytt for bruker
        dek_for_user_new = encrypt_dek_for_user(dek, kek_new)

        # 5) Skriv til DB
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET dek_for_user=%s WHERE id=%s",
                (dek_for_user_new, user_id),
            )

        print("dek_for_user oppdatert. Brukeren kan nå bruke det nye passordet i nettleseren.")

    finally:
        conn.close()


def main():
    if len(sys.argv) < 2:
        print("Bruk: python3 notes_crypto_admin.py [enroll|recover]")
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "enroll":
        enroll_user()
    elif mode == "recover":
        recover_user()
    else:
        print("Ukjent modus:", mode)
        print("Bruk: python3 notes_crypto_admin.py [enroll|recover]")
        sys.exit(1)


if __name__ == "__main__":
    main()