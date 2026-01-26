#!/usr/bin/env python3
"""
Nightly reminder email sender.
Run via cron or systemd timer, e.g. daily at 06:00:
  0 6 * * * /var/www/notes/api/venv/bin/python /var/www/notes/api/send_reminders.py

Reads config from /etc/notes-api.env (same as the API).
Finds reminders due today or earlier (not done), sends email with snooze links.
"""

import os
import sys
import smtplib
import secrets
import pymysql
from email.message import EmailMessage
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("send-reminders")

# Load env from file
ENV_FILE = os.getenv("ENV_FILE", "/etc/notes-api.env")
if os.path.isfile(ENV_FILE):
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "notes")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME", "notes")
SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "false").lower() == "true"
MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@example.com")

SNOOZE_BASE_URL = os.getenv(
    "NOTES_SNOOZE_BASE_URL",
    "https://hh-utdanning.nmbu.no/notes/api/reminders/snooze"
)


def send_reminder_email(to_email, to_name, title, stud_nr, reminder_date, snooze_token):
    msg = EmailMessage()
    msg["Subject"] = f"Påminnelse: {title} (student {stud_nr})"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email

    snooze_1d = f"{SNOOZE_BASE_URL}?token={snooze_token}&days=1"
    snooze_1w = f"{SNOOZE_BASE_URL}?token={snooze_token}&days=7"
    snooze_1m = f"{SNOOZE_BASE_URL}?token={snooze_token}&days=30"

    body = f"""Hei {to_name},

Du har en påminnelse for student {stud_nr}:

  {title}

Påminnelsesdato: {reminder_date}

---

Utsett påminnelsen:
  +1 dag:   {snooze_1d}
  +1 uke:   {snooze_1w}
  +1 måned: {snooze_1m}

Vennlig hilsen
Studentnotatsystemet
"""

    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        if SMTP_STARTTLS:
            server.starttls()
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def main():
    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4", autocommit=True
    )
    cur = conn.cursor()

    # Find reminders due today or earlier that haven't been sent
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d 23:59:59")
    cur.execute("""
        SELECT r.id, r.reminder_at, r.snooze_token,
               f.title,
               s.stud_nr,
               u.email, u.name
        FROM reminders r
        JOIN followup f ON f.id = r.followup_id
        JOIN notes n ON n.id = f.note_id
        JOIN students s ON s.id = n.student
        JOIN users u ON u.id = r.user_id
        WHERE r.done = 0 AND r.reminder_at <= %s
    """, (now,))
    rows = cur.fetchall()

    if not rows:
        logger.info("No reminders due. Exiting.")
        conn.close()
        return

    logger.info("Found %d reminder(s) to send.", len(rows))
    sent = 0

    for rid, reminder_at, snooze_token, title, stud_nr, email, name in rows:
        # Ensure snooze token exists
        if not snooze_token:
            snooze_token = secrets.token_urlsafe(32)
            cur.execute("UPDATE reminders SET snooze_token=%s WHERE id=%s", (snooze_token, rid))

        reminder_date_str = reminder_at.strftime("%Y-%m-%d") if reminder_at else "ukjent"

        try:
            send_reminder_email(email, name, title, stud_nr, reminder_date_str, snooze_token)
            cur.execute("UPDATE reminders SET done=1 WHERE id=%s", (rid,))
            sent += 1
            logger.info("Sent reminder #%d to %s (%s, student %s)", rid, email, title, stud_nr)
        except Exception as e:
            logger.exception("Failed to send reminder #%d to %s: %s", rid, email, e)

    conn.close()
    logger.info("Done. Sent %d/%d reminders.", sent, len(rows))


if __name__ == "__main__":
    main()
