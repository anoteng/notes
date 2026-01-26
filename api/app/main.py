import ast
from fastapi import FastAPI, Depends, HTTPException, Request, Response, Cookie
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import pymysql
import base64
import os
from contextlib import contextmanager
import secrets
import smtplib
from email.message import EmailMessage
from datetime import timedelta, datetime, timezone
import logging

# --- Konfig ---
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "notes")
DB_PASS = os.getenv("DB_PASS")  # ingen default!
DB_NAME = os.getenv("DB_NAME", "notes")
COOKIE_NAME = os.getenv("COOKIE_NAME", "notes_key")
SESSION_MAX_AGE = 30 * 24 * 60 * 60  # 30 days in seconds
raw = os.getenv("ALLOWED_ORIGINS", "[]")
ALLOWED_ORIGINS = ast.literal_eval(raw)

MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@example.com")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_USER = os.getenv("SMTP_USER")  # kan være None
SMTP_PASS = os.getenv("SMTP_PASS")  # kan være None
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "false").lower() == "true"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("notes-email")

def b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# Brukes til å lage lenke i e-posten
PUBLIC_BASE_URL = os.getenv(
    "NOTES_PUBLIC_BASE_URL",
    "https://hh-utdanning.nmbu.no/notes/login.html"
)

app = FastAPI(title="Notes API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.middleware("http")
async def refresh_session_cookie(request: Request, call_next):
    """Refresh session cookie on every authenticated request to extend session with activity."""
    response = await call_next(request)

    # Skip session endpoints - they manage their own cookies
    if request.url.path in ("/session/start", "/session/end"):
        return response

    # Only refresh if user is authenticated (cookie present and response is successful)
    notes_key = request.cookies.get(COOKIE_NAME)
    if notes_key and 200 <= response.status_code < 400:
        response.set_cookie(
            key=COOKIE_NAME, value=notes_key,
            httponly=True, secure=True, samesite="Lax",
            max_age=SESSION_MAX_AGE, path="/notes/api"
        )
    return response

@contextmanager
def db():
    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4", autocommit=True
    )
    try:
        yield conn
    finally:
        conn.close()

def generate_api_key() -> str:
    # 32 bytes → ~43 tegn URL-safe streng
    return secrets.token_urlsafe(32)


def send_magic_link_email(to_email: str, api_key: str):
    """
    Sender e-post med innloggingsnøkkel og klikkbar lenke.
    Bruker SMTP_* og MAIL_FROM-konfigen over.
    """

    msg = EmailMessage()
    msg["Subject"] = "Innloggingslenke til studentnotater"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email

    # Lenke med ?key= for enkel bruk
    login_link = f"{PUBLIC_BASE_URL}?key={api_key}"

    body = f"""Hei,

Her er innloggingsnøkkelen din til studentnotatsystemet:

Nøkkel:
{api_key}

Du kan enten lime inn nøkkelen på innloggingssiden,
eller klikke direkte på denne lenken:

{login_link}

Hvis du ikke ba om denne lenken, kan du se bort fra e-posten.

Vennlig hilsen
Studentnotatsystemet
"""

    msg.set_content(body)

    logger.info(
        "Forsøker å sende magic link til %s via %s:%s (STARTTLS=%s, USER=%s)",
        to_email, SMTP_HOST, SMTP_PORT, SMTP_STARTTLS, SMTP_USER or "<none>"
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.set_debuglevel(1)  # logger hele SMTP-dialogen til stdout/journal

            if SMTP_STARTTLS:
                logger.info("Starter STARTTLS...")
                server.starttls()

            if SMTP_USER and SMTP_PASS:
                logger.info("Logger inn på SMTP-server...")
                server.login(SMTP_USER, SMTP_PASS)

            server.send_message(msg)

        logger.info("Magic link til %s er sendt uten feil.", to_email)

    except Exception as e:
        logger.exception("Feil ved sending av magic link til %s: %s", to_email, e)
        # Du kan velge å la feilen boble opp, eller bare logge og la APIet late som "ok"
        raise

class StudentUpdateIn(BaseModel):
    graduated: bool

class SessionStartIn(BaseModel):
    key: str = Field(..., min_length=8)

class NoteCreateIn(BaseModel):
    student_id: int
    ciphertext_b64: str = Field(..., min_length=10)
    nonce_b64: str = Field(..., min_length=10)
    encryption_version: int = 1


class NoteUpdateIn(BaseModel):
    ciphertext_b64: str = Field(..., min_length=10)
    nonce_b64: str = Field(..., min_length=10)
    encryption_version: int = 1

class CryptoConfigOut(BaseModel):
    crypto_salt_b64: str
    dek_for_user_b64: Optional[str]

class DekUpdateIn(BaseModel):
    dek_for_user_b64: str = Field(..., min_length=10)

class RegisterIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    email: str = Field(..., min_length=5, max_length=128)


class MagicLinkIn(BaseModel):
    email: str = Field(..., min_length=5, max_length=128)


class RegisterOut(BaseModel):
    ok: bool
    message: str
    api_key: Optional[str] = None  # nyttig for testing/dev

class ReminderCreateIn(BaseModel):
    note_id: int
    title: str = Field(..., min_length=1, max_length=255)
    reminder_at: str = Field(..., min_length=10)  # ISO date string e.g. "2025-02-15"

class StudentCreateIn(BaseModel):
    stud_nr: str = Field(..., min_length=6, max_length=6)
    graduated: bool = False



def get_user_from_cookie(notes_key: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)):
    if not notes_key:
        logger.warning("Auth failed: Missing session cookie")
        raise HTTPException(status_code=401, detail="Missing session cookie")
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email, valid_until, active FROM users WHERE `api_key`=%s",
            (notes_key,)
        )
        row = cur.fetchone()
    if not row:
        logger.warning("Auth failed: Invalid session (key not found in DB)")
        raise HTTPException(status_code=401, detail="Invalid session")
    uid, name, email, valid_until, active = row
    valid_until = valid_until.replace(tzinfo=timezone.utc)
    if not active or (isinstance(valid_until, datetime) and valid_until < datetime.now(timezone.utc)):
        logger.warning("Auth failed: Session expired/inactive (active=%s, valid_until=%s)", active, valid_until)
        raise HTTPException(status_code=401, detail="Session expired/inactive")
    return {"id": uid, "name": name, "email": email}

@app.post("/register", response_model=RegisterOut)
def register_user(body: RegisterIn):
    # Normalize e-post
    email = body.email.strip().lower()
    name = body.name.strip()

    # Opprett eller oppdater bruker
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, active FROM users WHERE email=%s",
            (email,)
        )
        row = cur.fetchone()

        api_key = generate_api_key()
        valid_until = datetime.now(timezone.utc) + timedelta(days=60)  # f.eks. 1 år

        if row:
            user_id, active = row
            # Oppdater eksisterende bruker
            cur.execute(
                """
                UPDATE users
                SET name=%s, api_key=%s, valid_until=%s, active=1
                WHERE id=%s
                """,
                (name, api_key, valid_until, user_id)
            )
        else:
            # Ny bruker
            cur.execute(
                """
                INSERT INTO users (name, email, api_key, valid_until, active)
                VALUES (%s, %s, %s, %s, 1)
                """,
                (name, email, api_key, valid_until)
            )
            user_id = cur.lastrowid

    # Send e-post med nøkkel + lenke
    try:
        send_magic_link_email(email, api_key)
    except Exception as e:
        # Logg i journal, men ikke lek detaljer til klient
        print(f"Feil ved sending av e-post til {email}: {e}")
        # Brukeren er opprettet uansett – kanskje vil du returnere api_key i JSON
        return RegisterOut(
            ok=True,
            message="Bruker opprettet, men e-posten feilet. Kontakt administrator for innloggingsnøkkel.",
            api_key=api_key,  # du kan fjerne dette i prod hvis du vil
        )

    return RegisterOut(
        ok=True,
        message="Brukeren er opprettet / oppdatert. Du får en e-post med innloggingslenke.",
        api_key=api_key  # behagelig for intern testing
    )

@app.post("/magic-link")
def magic_link(body: MagicLinkIn):
    email = body.email.strip().lower()

    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, active FROM users WHERE email=%s",
            (email,)
        )
        row = cur.fetchone()

        # For ikke å lekke om e-post finnes eller ikke, gir vi samme svar uansett.
        if not row:
            # Lat som alt gikk fint
            return {"ok": True, "message": "Hvis e-posten finnes i systemet, får du snart en lenke."}

        user_id, active = row

        api_key = generate_api_key()
        valid_until = datetime.now(timezone.utc) + timedelta(days=60)

        cur.execute(
            """
            UPDATE users
            SET api_key=%s, valid_until=%s, active=1
            WHERE id=%s
            """,
            (api_key, valid_until, user_id)
        )

    try:
        send_magic_link_email(email, api_key)
    except Exception as e:
        print(f"Feil ved sending av magic link til {email}: {e}")
        # Igjen: ikke lek detaljer til sluttbruker
        return {"ok": True, "message": "Hvis e-posten finnes i systemet, får du snart en lenke."}

    return {"ok": True, "message": "Hvis e-posten finnes i systemet, får du snart en lenke."}


@app.post("/session/start")
def session_start(body: SessionStartIn, response: Response):
    # Bekreft at nøkkelen er gyldig, sett cookie (HttpOnly + SameSite=Lax)
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, valid_until, active FROM users WHERE `api_key`=%s",
            (body.key,)
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid key")
    _, valid_until, active = row
    valid_until = valid_until.replace(tzinfo=timezone.utc)
    if not active or (isinstance(valid_until, datetime) and valid_until < datetime.now(timezone.utc)):
        raise HTTPException(status_code=401, detail="Key expired/inactive")

    # Sett cookie – HttpOnly, Secure og fornuftig path
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key=COOKIE_NAME, value=body.key,
        httponly=True, secure=True, samesite="Lax",
        max_age=SESSION_MAX_AGE, path="/notes/api"   # 30 days
    )
    return response

@app.post("/session/end")
def session_end(response: Response):
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/notes/api")
    return response

@app.get("/students")
def list_students(q: Optional[str] = None, user=Depends(get_user_from_cookie)):
    params = []
    sql = "SELECT id, stud_nr, graduated FROM students"
    if q:
        sql += " WHERE CAST(stud_nr AS CHAR) LIKE %s"
        params.append(f"%{q}%")
    sql += " ORDER BY id DESC LIMIT 200"
    with db() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
    return [{"id": r[0], "stud_nr": r[1], "graduated": bool(r[2])} for r in rows]

@app.get("/notes/{student_id}")
def list_notes(student_id: int, user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT n.id, n.owner, n.student, n.note_ciphertext, n.nonce,
                   n.created_at, n.updated_at, n.encryption_version
            FROM notes n
            WHERE n.student=%s AND n.owner=%s AND n.deleted = 0
            ORDER BY n.id DESC
        """, (student_id, user["id"]))
        rows = cur.fetchall()

    result = []
    for (rid, owner, student, note_ciphertext, nonce, created, updated, enc_ver) in rows:
        result.append({
            "id": rid,
            "owner": owner,
            "student": student,
            "ciphertext_b64": note_ciphertext,           # lagres som tekst i DB
            "nonce_b64": b64encode(nonce) if nonce else None,
            "created": created,
            "updated": updated,
            "encryption_version": enc_ver,
        })

    return result

@app.post("/notes")
def create_note(body: NoteCreateIn, user=Depends(get_user_from_cookie)):
    nonce_bytes = b64decode(body.nonce_b64)

    with db() as conn:
        cur = conn.cursor()
        # Sikre at student finnes
        cur.execute("SELECT id FROM students WHERE id=%s", (body.student_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Student not found")

        cur.execute(
            """
            INSERT INTO notes (owner, student, note_ciphertext, nonce, encryption_version)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user["id"], body.student_id, body.ciphertext_b64, nonce_bytes, body.encryption_version)
        )
        note_id = cur.lastrowid
        cur.execute("SELECT created_at, updated_at FROM notes WHERE id=%s", (note_id,))
        created, updated = cur.fetchone()

    return {
        "id": note_id,
        "created": created,
        "updated": updated,
        "encryption_version": body.encryption_version,
    }


@app.put("/notes/{note_id}")
def update_note(note_id: int, body: NoteUpdateIn, user=Depends(get_user_from_cookie)):
    nonce_bytes = b64decode(body.nonce_b64)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT owner FROM notes WHERE id=%s", (note_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Note not found")
        if row[0] != user["id"]:
            raise HTTPException(status_code=403, detail="Not your note")

        cur.execute(
            """
            UPDATE notes
            SET note_ciphertext=%s, nonce=%s, encryption_version=%s
            WHERE id=%s
            """,
            (body.ciphertext_b64, nonce_bytes, body.encryption_version, note_id)
        )
        cur.execute("SELECT updated_at FROM notes WHERE id=%s", (note_id,))
        updated = cur.fetchone()[0]

    return {"id": note_id, "updated": updated, "encryption_version": body.encryption_version}


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE notes SET deleted = 1 WHERE id=%s AND owner=%s",
            (note_id, user["id"])
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Note not found or not yours")
    return {"ok": True}


@app.get("/crypto/config", response_model=CryptoConfigOut)
def get_crypto_config(user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT crypto_salt, dek_for_user FROM users WHERE id=%s",
            (user["id"],)
        )
        row = cur.fetchone()

    crypto_salt, dek_for_user = row if row else (None, None)

    # Generer crypto_salt hvis mangler
    if crypto_salt is None:
        crypto_salt = os.urandom(16)
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET crypto_salt=%s WHERE id=%s",
                (crypto_salt, user["id"])
            )

    return CryptoConfigOut(
        crypto_salt_b64=b64encode(crypto_salt),
        dek_for_user_b64=b64encode(dek_for_user) if dek_for_user is not None else None,
    )


@app.post("/crypto/dek")
def set_dek(body: DekUpdateIn, user=Depends(get_user_from_cookie)):
    dek_bytes = b64decode(body.dek_for_user_b64)

    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET dek_for_user=%s WHERE id=%s",
            (dek_bytes, user["id"])
        )

    return {"ok": True}

@app.post("/students")
def create_student(body: StudentCreateIn, user=Depends(get_user_from_cookie)):
    stud_nr = body.stud_nr.strip()
    graduated = 1 if body.graduated else 0

    with db() as conn:
        cur = conn.cursor()

        # Sjekk om studentnummer allerede finnes
        cur.execute(
            "SELECT id FROM students WHERE stud_nr=%s",
            (stud_nr,)
        )
        row = cur.fetchone()
        if row:
            raise HTTPException(status_code=400, detail="Studentnummeret finnes allerede.")

        # Opprett student
        cur.execute(
            "INSERT INTO students (stud_nr, graduated) VALUES (%s, %s)",
            (stud_nr, graduated)
        )
        student_id = cur.lastrowid

    return {
        "id": student_id,
        "stud_nr": stud_nr,
        "graduated": bool(graduated),
    }
@app.put("/students/{student_id}")
def update_student(student_id: int, body: StudentUpdateIn, user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, stud_nr, graduated FROM students WHERE id=%s",
            (student_id,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Student not found")

        cur.execute(
            "UPDATE students SET graduated=%s WHERE id=%s",
            (1 if body.graduated else 0, student_id)
        )

        return {
            "id": student_id,
            "graduated": body.graduated,
        }


# --- Reminders ---

@app.post("/reminders")
def create_reminder(body: ReminderCreateIn, user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        # Verify note belongs to user
        cur.execute(
            "SELECT id FROM notes WHERE id=%s AND owner=%s AND deleted=0",
            (body.note_id, user["id"])
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Note not found or not yours")

        # Parse date
        try:
            reminder_dt = datetime.strptime(body.reminder_at, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format, use YYYY-MM-DD")

        # Create followup
        cur.execute(
            "INSERT INTO followup (note_id, title, finished) VALUES (%s, %s, 0)",
            (body.note_id, body.title.strip())
        )
        followup_id = cur.lastrowid

        # Create reminder with snooze token
        token = secrets.token_urlsafe(32)
        cur.execute(
            "INSERT INTO reminders (followup_id, reminder_at, user_id, done, snooze_token) VALUES (%s, %s, %s, 0, %s)",
            (followup_id, reminder_dt, user["id"], token)
        )
        reminder_id = cur.lastrowid

    return {"ok": True, "id": reminder_id, "followup_id": followup_id}


@app.get("/reminders")
def list_reminders(user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT r.id, r.reminder_at, r.done,
                   f.title, f.note_id,
                   s.id AS student_id, s.stud_nr
            FROM reminders r
            JOIN followup f ON f.id = r.followup_id
            JOIN notes n ON n.id = f.note_id
            JOIN students s ON s.id = n.student
            WHERE r.user_id = %s AND r.done = 0
            ORDER BY r.reminder_at ASC
        """, (user["id"],))
        rows = cur.fetchall()

    return [
        {
            "id": r[0],
            "reminder_at": r[1].strftime("%Y-%m-%d") if r[1] else None,
            "done": bool(r[2]),
            "title": r[3],
            "note_id": r[4],
            "student_id": r[5],
            "stud_nr": r[6],
        }
        for r in rows
    ]


@app.delete("/reminders/{reminder_id}")
def delete_reminder(reminder_id: int, user=Depends(get_user_from_cookie)):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE reminders SET done=1 WHERE id=%s AND user_id=%s",
            (reminder_id, user["id"])
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Reminder not found or not yours")
    return {"ok": True}


@app.get("/reminders/snooze")
def snooze_reminder(token: str, days: int):
    """Snooze a reminder via email link. No login required — token authenticates."""
    if days not in (1, 7, 30):
        return HTMLResponse("<html><body><h2>Ugyldig antall dager.</h2></body></html>", status_code=400)

    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, reminder_at FROM reminders WHERE snooze_token=%s",
            (token,)
        )
        row = cur.fetchone()
        if not row:
            return HTMLResponse(
                "<html><body><h2>Ugyldig eller utløpt lenke.</h2>"
                "<p>Påminnelsen finnes ikke eller er allerede håndtert.</p></body></html>",
                status_code=404
            )

        reminder_id, current_at = row
        new_date = datetime.now(timezone.utc) + timedelta(days=days)
        new_token = secrets.token_urlsafe(32)

        cur.execute(
            "UPDATE reminders SET reminder_at=%s, done=0, snooze_token=%s WHERE id=%s",
            (new_date, new_token, reminder_id)
        )

    days_label = {1: "1 dag", 7: "1 uke", 30: "1 måned"}[days]
    return HTMLResponse(
        f"<html><head><meta charset='utf-8'><title>Påminnelse utsatt</title>"
        f"<style>body{{font-family:sans-serif;max-width:500px;margin:80px auto;text-align:center}}</style></head>"
        f"<body><h2>Påminnelse utsatt med {days_label}</h2>"
        f"<p>Ny dato: {new_date.strftime('%Y-%m-%d')}</p>"
        f"<p>Du kan lukke dette vinduet.</p></body></html>"
    )