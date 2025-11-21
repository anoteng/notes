from fastapi import FastAPI, Depends, HTTPException, Request, Response, Cookie
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import pymysql
import base64
import os
from datetime import datetime
from contextlib import contextmanager

# --- Konfig ---
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "notes")
DB_PASS = os.getenv("DB_PASS")  # ingen default!
DB_NAME = os.getenv("DB_NAME", "notes")
COOKIE_NAME = os.getenv("COOKIE_NAME", "notes_key")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS")

def b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


app = FastAPI(title="Notes API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

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


def get_user_from_cookie(notes_key: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)):
    if not notes_key:
        raise HTTPException(status_code=401, detail="Missing session cookie")
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email, valid_until, active FROM users WHERE `key`=%s",
            (notes_key,)
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid session")
    uid, name, email, valid_until, active = row
    if not active or (isinstance(valid_until, datetime) and valid_until < datetime.utcnow()):
        raise HTTPException(status_code=401, detail="Session expired/inactive")
    return {"id": uid, "name": name, "email": email}

@app.post("/session/start")
def session_start(body: SessionStartIn, response: Response):
    # Bekreft at nøkkelen er gyldig, sett cookie (HttpOnly + SameSite=Lax)
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, valid_until, active FROM users WHERE `key`=%s",
            (body.key,)
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid key")
    _, valid_until, active = row
    if not active or (isinstance(valid_until, datetime) and valid_until < datetime.utcnow()):
        raise HTTPException(status_code=401, detail="Key expired/inactive")

    # Sett cookie – HttpOnly, Secure og fornuftig path
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key=COOKIE_NAME, value=body.key,
        httponly=True, secure=True, samesite="Lax",
        max_age=8*60*60, path="/notes/api"   # 8 timer
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

