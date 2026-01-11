# lynqrbot

full implementation
Features:
- Telegram async bot (python-telegram-bot v20+)
- VirusTotal + urlscan.io checks with retries
- Multiple QR detection + preprocessing (noisy images)
- Classify QR payloads: url, tel, wifi, vcard, text
- Buttons: retry urlscan, check final redirect, show urlscan report
- Firebase Realtime DB logging (async)
- Per-user request limits (stored in Firebase)
- Admin commands: /admin (stats), /logs N (recent logs)
