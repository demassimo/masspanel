#!/usr/bin/env python3
"""Sort the hidden receive-only MassPanel archive mailbox."""
import imaplib
import json
import os
import ssl

mailbox = os.environ["SYSTEM_MAILBOX"]
with open(os.environ["SYSTEM_MAILBOX_CREDENTIALS"], encoding="utf-8") as stream:
    password = json.load(stream)[mailbox]
folders = {
    "postmaster@": "System/Postmaster",
    "abuse@": "System/Abuse reports",
    "webmaster@": "System/Website notices",
    "root@": "System/Root and server",
}
client = imaplib.IMAP4("127.0.0.1", 143)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
client.starttls(ssl_context=context)
client.login(mailbox, password)
client.create("System")
for folder in set(folders.values()): client.create(folder)
client.create("System/Other")
client.select("INBOX")
status, data = client.uid("search", None, "ALL")
if status == "OK":
    for uid in data[0].split():
        status, message = client.uid("fetch", uid, "(BODY.PEEK[HEADER.FIELDS (X-ORIGINAL-TO DELIVERED-TO TO)])")
        if status != "OK" or not message or not isinstance(message[0], tuple): continue
        headers = message[0][1].decode("utf-8", "replace").lower()
        target = next((folder for marker, folder in folders.items() if marker in headers), "System/Other")
        moved, _ = client.uid("MOVE", uid, target)
        if moved != "OK":
            copied, _ = client.uid("COPY", uid, target)
            if copied == "OK": client.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
    client.expunge()
client.logout()
