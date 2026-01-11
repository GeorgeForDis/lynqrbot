#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LynqrBot — full implementation
Features:
- Telegram async bot (python-telegram-bot v20+)
- VirusTotal + urlscan.io checks with retries
- Multiple QR detection + preprocessing (noisy images)
- Classify QR payloads: url, tel, wifi, vcard, text
- Buttons: retry urlscan, check final redirect, show urlscan report
- Firebase Realtime DB logging (async)
- Per-user request limits (stored in Firebase)
- Admin commands: /admin (stats), /logs N (recent logs)
"""

import os
import re
import io
import time
import json
import glob
import logging
import asyncio
import ssl
from typing import Optional, Tuple, Dict, Any, List

from dotenv import load_dotenv
load_dotenv()

# Try to auto-add zbar library path on macOS (Homebrew)
def ensure_zbar_path():
    candidates = [
        "/opt/homebrew/Cellar/zbar/*/lib",
        "/usr/local/Cellar/zbar/*/lib",
        "/opt/homebrew/lib",
        "/usr/local/lib",
        "/usr/lib"
    ]
    found = None
    for pat in candidates:
        for p in glob.glob(pat):
            if any(glob.glob(os.path.join(p, "libzbar*"))):
                found = p
                break
        if found:
            break
    if found:
        prev = os.environ.get("DYLD_LIBRARY_PATH", "")
        os.environ["DYLD_LIBRARY_PATH"] = found + (":" + prev if prev else "")
        # Set ZBAR_LIB to first dylib (pyzbar will pick it up)
        libs = glob.glob(os.path.join(found, "libzbar*.dylib"))
        if libs:
            os.environ["ZBAR_LIB"] = libs[0]

ensure_zbar_path()

# Import pyzbar after environment tweak
try:
    from pyzbar.pyzbar import decode
except Exception as e:
    raise RuntimeError("pyzbar import failed — ensure zbar is installed and DYLD_LIBRARY_PATH points to its lib dir") from e

from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import aiohttp
import certifi

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)

# ---------------------------
# Config (from env or defaults)
# ---------------------------
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "YOUR_TELEGRAM_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VT_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "YOUR_URLSCAN_KEY")
FIREBASE_URL = os.getenv("FIREBASE_URL", "").rstrip("/")  # e.g. https://...firebaseio.com
ADMIN_IDS = set(int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip())

# Rate limiting
REQUEST_LIMIT = int(os.getenv("REQUEST_LIMIT", "30"))     # e.g. 30 checks
LIMIT_WINDOW = int(os.getenv("LIMIT_WINDOW", str(3600)))  # seconds (1 hour)

# aiohttp ssl context using certifi
SSL_CTX = ssl.create_default_context(cafile=certifi.where())

# URLScan / VirusTotal endpoints
VT_SUBMIT = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSES = "https://www.virustotal.com/api/v3/analyses/"
URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LynqrBot")

# ---------------------------
# Helpers: extractors & QR utils
# ---------------------------
URL_RE = re.compile(r"(https?://[^\s\)\]\}\,]+)", flags=re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9\-]+\.)+[a-z]{2,6}\b(/[^\s]*)?", flags=re.IGNORECASE)
TEL_RE = re.compile(r"tel:?\+?[\d\-\(\) ]+", flags=re.IGNORECASE)
VCARD_PREFIXES = ("BEGIN:VCARD", "MECARD:")

def extract_url_from_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    # prefer explicit URLs
    m = URL_RE.search(text)
    if m:
        return m.group(1).rstrip(".,;)")
    # fallback: bare domain -> prepend http
    m2 = DOMAIN_RE.search(text)
    if m2:
        return "http://" + m2.group(0)
    return None

def classify_qr_payload(payload: str) -> Tuple[str, Optional[str]]:
    p = payload.strip()
    low = p.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return "url", p
    if low.startswith("tel:") or TEL_RE.search(low):
        return "tel", p
    if low.startswith("wifi:") or low.startswith("wifi:".upper()):
        return "wifi", p
    for s in VCARD_PREFIXES:
        if p.upper().startswith(s):
            return "vcard", p
    # domain without scheme
    if re.match(r"^[\w\-\_\.]+\.[a-z]{2,6}(/.*)?$", p, flags=re.IGNORECASE):
        return "url", "http://" + p
    return "text", p

def preprocess_image_for_qr(img: Image.Image) -> Image.Image:
    try:
        img = img.convert("L")  # grayscale
        img = ImageEnhance.Contrast(img).enhance(1.6)
        img = img.filter(ImageFilter.MedianFilter(size=3))
        max_side = max(img.size)
        if max_side < 1000:
            scale = 1000 / max_side
            img = img.resize((int(img.width*scale), int(img.height*scale)), Image.Resampling.LANCZOS)
        img = ImageOps.autocontrast(img)
        return img
    except Exception:
        return img

# ---------------------------
# Firebase async helpers
# ---------------------------
async def firebase_push(session: aiohttp.ClientSession, path: str, payload: dict):
    """POST -> creates new child (push)"""
    if not FIREBASE_URL:
        return
    url = f"{FIREBASE_URL}/{path}.json"
    try:
        async with session.post(url, json=payload, ssl=SSL_CTX, timeout=10) as r:
            return await r.json()
    except Exception as e:
        logger.debug("Firebase push error: %s", e)
        return None

async def firebase_get(session: aiohttp.ClientSession, path: str):
    if not FIREBASE_URL:
        return None
    url = f"{FIREBASE_URL}/{path}.json"
    try:
        async with session.get(url, ssl=SSL_CTX, timeout=10) as r:
            return await r.json()
    except Exception as e:
        logger.debug("Firebase get error: %s", e)
        return None

async def firebase_set(session: aiohttp.ClientSession, path: str, payload: dict):
    if not FIREBASE_URL:
        return None
    url = f"{FIREBASE_URL}/{path}.json"
    try:
        async with session.put(url, json=payload, ssl=SSL_CTX, timeout=10) as r:
            return await r.json()
    except Exception as e:
        logger.debug("Firebase set error: %s", e)
        return None

async def log_scan(user_id: int, url: str, vt_res: dict, us_res: dict):
    async with aiohttp.ClientSession() as session:
        payload = {
            "timestamp": int(time.time()),
            "user": user_id,
            "url": url,
            "vt": vt_res,
            "urlscan": us_res
        }
        await firebase_push(session, "logs", payload)

async def log_error(user_id: Optional[int], url: Optional[str], error: str):
    async with aiohttp.ClientSession() as session:
        payload = {"timestamp": int(time.time()), "user": user_id, "url": url, "error": str(error)}
        await firebase_push(session, "errors", payload)

# ---------------------------
# Rate limit functions (per-user)
# ---------------------------
async def check_and_update_limit(user_id: int) -> bool:
    """
    Returns True if allowed; False if limit exceeded.
    Stored at /limits/{user_id} = {"count": N, "reset": timestamp}
    """
    async with aiohttp.ClientSession() as session:
        cur = await firebase_get(session, f"limits/{user_id}")
        now = int(time.time())
        if not cur:
            # create
            await firebase_set(session, f"limits/{user_id}", {"count": 1, "reset": now + LIMIT_WINDOW})
            return True
        count = cur.get("count", 0)
        reset = cur.get("reset", now + LIMIT_WINDOW)
        if now > reset:
            await firebase_set(session, f"limits/{user_id}", {"count": 1, "reset": now + LIMIT_WINDOW})
            return True
        if count >= REQUEST_LIMIT:
            return False
        await firebase_set(session, f"limits/{user_id}", {"count": count + 1, "reset": reset})
        return True

# ---------------------------
# Networking: expand short URLs and check VT + URLScan
# ---------------------------
async def expand_short_url(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.head(url, allow_redirects=True, timeout=15, ssl=SSL_CTX) as r:
            return str(r.url)
    except Exception:
        try:
            async with session.get(url, allow_redirects=True, timeout=15, ssl=SSL_CTX) as r2:
                return str(r2.url)
        except Exception:
            return url

async def vt_check(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        async with session.post(VT_SUBMIT, headers=headers, data={"url": url}, ssl=SSL_CTX, timeout=30) as resp:
            data = await resp.json()
    except Exception as e:
        return {"error": f"vt_submit_err:{e}"}
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        return {"error": "vt_no_analysis_id", "raw": data}
    await asyncio.sleep(2)
    try:
        async with session.get(VT_ANALYSES + analysis_id, headers=headers, ssl=SSL_CTX, timeout=30) as resp2:
            report = await resp2.json()
    except Exception as e:
        return {"error": f"vt_fetch_err:{e}"}
    stats = report.get("data", {}).get("attributes", {}).get("stats", {})
    return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "raw": report}

async def urlscan_check(session: aiohttp.ClientSession, url: str, retries: int = 4, delay: float = 3.0) -> Dict[str, Any]:
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    try:
        async with session.post(URLSCAN_SUBMIT, json={"url": url, "visibility": "private"}, headers=headers, ssl=SSL_CTX, timeout=30) as r:
            data = await r.json()
    except Exception as e:
        return {"error": f"urlscan_submit_err:{e}"}
    uuid = data.get("uuid")

    if not uuid:
        return {
            "error": "urlscan_no_uuid",
            "raw": data
        }

    api_url = f"https://urlscan.io/api/v1/result/{uuid}/"
    public_url = f"https://urlscan.io/result/{uuid}/"

    # Try polling
    for attempt in range(retries):
        try:
            await asyncio.sleep(delay if attempt else 0)
            async with session.get(api_url, ssl=SSL_CTX, timeout=30) as r2:
                if r2.status == 200:
                    res = await r2.json()
                    verdicts = res.get("verdicts", {})
                    score = verdicts.get("overall", {}).get("score", 0)
                    brand = None
                    brand_info = verdicts.get("brand", [])
                    if isinstance(brand_info, list) and brand_info:
                        brand = brand_info[0].get("brand")
                    return {
                        "score": score,
                        "malicious": score > 0,
                        "brand_misuse": brand,
                        "result_url": public_url,
                        "uuid": uuid,
                        "raw": res
                    }

                else:
                    # not ready: continue
                    text = await r2.text()
        except Exception as e:
            logger.debug("urlscan poll exception: %s", e)
        # exponential-ish backoff
        await asyncio.sleep(delay * (attempt + 1))
    return {
        "error": "urlscan_timeout",
        "result_url": public_url,
        "uuid": uuid,
        "raw_submit": data
    }


# ---------------------------
# Combine results -> verdict
# ---------------------------
def combine_vt_urlscan(vt: Dict[str, Any], us: Dict[str, Any]) -> Tuple[str, int]:
    risk = 0
    if "malicious" in vt:
        risk += vt.get("malicious", 0) * 50
        risk += vt.get("suspicious", 0) * 20
    if "score" in us:
        risk += us.get("score", 0) * 10
    if us.get("brand_misuse"):
        risk += 60
    if risk > 120:
        return "HIGH", risk
    if risk > 50:
        return "MEDIUM", risk
    return "LOW", risk

# ---------------------------
# Threat Report Generator
# ---------------------------

def build_threat_report(url: str, heur: dict, vt: dict, us: dict) -> str:
    lines = []
    lines.append("🛡 Threat Report")
    lines.append(f"🔗 URL: {url}")
    lines.append("")

    # --- Heuristics ---
    if heur["reasons"]:
        lines.append("🔍 Обнаруженные признаки:")
        for r in heur["reasons"]:
            mitre = MITRE_MAPPING.get(r)
            if mitre:
                lines.append(
                    f"• {r}\n"
                    f"  ↳ MITRE ATT&CK {mitre['technique']} — "
                    f"{mitre['name']} ({mitre['stage']})"
                )
            else:
                lines.append(f"• {r}")
        lines.append("")

    # --- VirusTotal ---
    if vt.get("error"):
        lines.append(f"⚠️ VirusTotal: ошибка анализа ({vt.get('error')})")
    else:
        lines.append(
            "🧪 VirusTotal:\n"
            f"• malicious: {vt.get('malicious', 0)}\n"
            f"• suspicious: {vt.get('suspicious', 0)}"
        )

    # --- URLScan ---
    if us.get("error"):
        lines.append(f"⚠️ URLScan: ошибка анализа ({us.get('error')})")
    else:
        lines.append(
            "🌐 URLScan:\n"
            f"• score: {us.get('score', 0)}"
        )
        if us.get("brand_misuse"):
            lines.append(f"• brand misuse: {us.get('brand_misuse')}")
        if us.get("result_url"):
            lines.append(f"• report: {us.get('result_url')}")

    # --- Clean verdict ---
    if (
        not heur["reasons"]
        and vt.get("malicious", 0) == 0
        and vt.get("suspicious", 0) == 0
        and not us.get("brand_misuse")
    ):
        lines.append("\n✅ Явных признаков фишинга не обнаружено")

    return "\n".join(lines)

# ---------------------------
# Meme detector
# ---------------------------
def detect_meme(url: str) -> Optional[str]:
    low = url.lower()
    if "dqw4w9wgxcq" in low or "rickroll" in low or "youtu.be/dq" in low:
        return "rickroll"
    if "jumpscare" in low or "screamer" in low or "omfgdogs" in low:
        return "screamer"
    return None

# ---------------------------
# Threat Report + MITRE ATT&CK
# ---------------------------


from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "password", "auth", "bank"
]

MITRE_MAPPING = {
    "IP-адрес вместо домена": {
        "technique": "T1566.002",
        "name": "Phishing: Link",
        "stage": "Initial Access"
    },
    "Punycode-домен": {
        "technique": "T1566.002",
        "name": "Homograph Attack",
        "stage": "Initial Access"
    },
    "Много поддоменов": {
        "technique": "T1566.002",
        "name": "Fake Subdomains",
        "stage": "Initial Access"
    },
    "Очень длинный URL": {
        "technique": "T1027",
        "name": "Obfuscated Information",
        "stage": "Defense Evasion"
    }
}

def heuristic_url_score(url: str) -> dict:
    score = 0
    reasons = []

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if re.match(r"\d+\.\d+\.\d+\.\d+", host):
        score += 30
        reasons.append("IP-адрес вместо домена")

    if host.startswith("xn--"):
        score += 40
        reasons.append("Punycode-домен")

    if host.count(".") >= 4:
        score += 15
        reasons.append("Много поддоменов")

    if len(url) > 120:
        score += 10
        reasons.append("Очень длинный URL")

    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            score += 5
            reasons.append(f"Ключевое слово: {word}")

    return {
        "score": score,
        "reasons": list(set(reasons))
    }


# ---------------------------
# Telegram handlers
# ---------------------------
START_KBD = InlineKeyboardMarkup([
    [InlineKeyboardButton("🛡 Проверить ссылку", callback_data="scan")],
    [InlineKeyboardButton("🎓 Demo Mode (для защиты)", callback_data="demo")],
    [InlineKeyboardButton("ℹ️ Помощь", callback_data="help")],
    [InlineKeyboardButton("📊 Админ", callback_data="admin")],
])

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Привет! Я LynqrBot. Отправь ссылку или фото с QR.", reply_markup=START_KBD)

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data or ""
    # redirect check
    if data.startswith("redirect:"):
        url = data.split(":",1)[1]
        session = aiohttp.ClientSession()
        try:
            # perform HEAD then GET to find final redirect
            async with session.head(url, allow_redirects=True, ssl=SSL_CTX) as r:
                final = str(r.url)
        except Exception:
            try:
                async with session.get(url, allow_redirects=True, ssl=SSL_CTX) as r2:
                    final = str(r2.url)
            except Exception as e:
                final = f"Ошибка: {e}"
        await query.edit_message_text(f"Конечный URL: {final}")
        await session.close()
        return
    # urlscan retry
    if data.startswith("urlscan_retry:"):
        url = data.split(":",1)[1]
        async with aiohttp.ClientSession() as session:
            us = await urlscan_check(session, url, retries=3, delay=3.0)
        if us.get("error"):
            await query.edit_message_text(f"URLScan всё ещё вернул ошибку: {us.get('error')}")
        else:
            await query.edit_message_text(f"URLScan готов: {us.get('result_url') or us.get('result')}")
        return
    # show urlscan
    if data.startswith("urlscan_show:"):
        url = data.split(":",1)[1]
        async with aiohttp.ClientSession() as session:
            us = await urlscan_check(session, url, retries=1, delay=1.0)
        if us.get("error"):
            await query.edit_message_text(f"URLScan ошибка: {us.get('error')}")
        else:
            await query.edit_message_text(f"URLScan отчет: {us.get('result_url') or us.get('result')}")
        return
    if data == "help":
        await query.edit_message_text("Отправь ссылку или фото с QR. Я проверю ссылку через VirusTotal + urlscan.")
        return
    if data == "scan":
        await query.edit_message_text("Отправь ссылку, и я её просканирую.")
        return
    if data == "admin":
        user_id = query.from_user.id
        if user_id not in ADMIN_IDS:
            await query.edit_message_text("Вы не админ.")
            return
        # fetch simple stats
        async with aiohttp.ClientSession() as session:
            logs = await firebase_get(session, "logs") or {}
            errors = await firebase_get(session, "errors") or {}
            limits = await firebase_get(session, "limits") or {}
        msg = f"📊 Статистика:\nЛогов: {len(logs)}\nОшибок: {len(errors)}\nПользователей (лимиты): {len(limits)}"
        await query.edit_message_text(msg)
        return
    # demo mode
    if data == "demo":
        demo_url = "http://xn--pple-43d.com/login"
        heur = heuristic_url_score(demo_url)

        vt_fake = {"malicious": 0, "suspicious": 1}
        us_fake = {"score": 6, "brand_misuse": "Apple"}

        base_level, base_score = combine_vt_urlscan(vt_fake, us_fake)
        score = base_score + heur["score"]

        report = build_threat_report(demo_url, heur, vt_fake, us_fake)

        await query.edit_message_text(
            "🎓 Demo Mode — демонстрация фишинговой атаки\n\n"
            f"🔎 Вердикт: {base_level} (score {score})\n\n"
            f"{report}"
        )
        return

async def analyze_and_reply(update: Update, context: ContextTypes.DEFAULT_TYPE, url: str):
    user_id = update.effective_user.id if update.effective_user else None
    # Check rate limit
    if user_id:
        allowed = await check_and_update_limit(user_id)
        if not allowed:
            await update.message.reply_text("⛔ Вы превысили лимит запросов. Подождите и попробуйте позже.")
            return
    # expand short url
    async with aiohttp.ClientSession() as session:
        try:
            final = await expand_short_url(session, url)
        except Exception:
            final = url
        # meme check
        mm = detect_meme(final)
        if mm:
            await update.message.reply_text(f"🥚 Пасхалка: {mm} — проверяю всё равно...")
        await update.message.reply_text("🔍 Проверяю (VirusTotal + urlscan). Это займёт ~5–20 секунд...")
        vt_task = vt_check(session, final)
        us_task = urlscan_check(session, final)
        try:
            vt_res, us_res = await asyncio.gather(vt_task, us_task)
        except Exception as e:
            await update.message.reply_text(f"Ошибка при выполнении сетевых запросов: {e}")
            await log_error(user_id, final, str(e))
            return
    # Log results to Firebase
    await log_scan(user_id, final, vt_res, us_res)
    # Build reply
    parts = []
    if vt_res.get("error"):
        parts.append(f"VirusTotal: ошибка ({vt_res.get('error')})")
    else:
        parts.append(f"VirusTotal — malicious: {vt_res.get('malicious',0)}, suspicious: {vt_res.get('suspicious',0)}")
    if us_res.get("error"):
        parts.append(f"URLScan: ошибка ({us_res.get('error')})")
    else:
        parts.append(f"URLScan — score: {us_res.get('score',0)}")
    heur = heuristic_url_score(final)
    level, score = combine_vt_urlscan(vt_res, us_res)
    score += heur["score"]  # усиливаем риск эвристикой

    report = build_threat_report(final, heur, vt_res, us_res)

    reply_text = (
        f"🔎 Итоговый вердикт: {level} (score {score})\n\n"
        f"{report}"
    )
    # Buttons: redirect, urlscan retry/show
    kb = [
        [InlineKeyboardButton("🔁 Проверить конечный редирект", callback_data=f"redirect:{final}")],
    ]
    if us_res.get("error") == "urlscan_no_result" or us_res.get("error") == "urlscan_timeout":
        kb.append([InlineKeyboardButton("🔄 Повторный скан URLScan", callback_data=f"urlscan_retry:{final}")])
    else:
        # show report link if present
        result_link = us_res.get("result_url") or us_res.get("result")
        if result_link:
            kb.append([InlineKeyboardButton("🔎 Показать URLScan", callback_data=f"urlscan_show:{final}")])
    await update.message.reply_text(reply_text, reply_markup=InlineKeyboardMarkup(kb))

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return

    # Prefer message.entities if includes url/text_link
    text_to_scan = ""
    ents = update.message.entities or []
    for ent in ents:
        if ent.type in ("url", "text_link"):
            if ent.type == "text_link" and ent.url:
                text_to_scan = ent.url
            else:
                text_to_scan = update.message.text[ent.offset:ent.offset+ent.length]
            break
    if not text_to_scan:
        text_to_scan = update.message.text or ""
    url = extract_url_from_text(text_to_scan)
    if not url:
        # answer only in direct
        if update.message.chat.type == "private":
            await update.message.reply_text(
                "Я не нашёл ссылку. Отправь чистую ссылку (например https://example.com)."
            )
        return

    await analyze_and_reply(update, context, url)

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.photo:
        return
    try:
        file = await update.message.photo[-1].get_file()
        b = await file.download_as_bytearray()
        img = Image.open(io.BytesIO(b))
    except Exception as e:
        await update.message.reply_text(f"Ошибка чтения изображения: {e}")
        return
    # preprocess
    proc = preprocess_image_for_qr(img)
    decoded = decode(proc)
    if not decoded:
        decoded = decode(img)
    if not decoded:
        alt = ImageOps.autocontrast(proc)
        decoded = decode(alt)
    if not decoded:
        await update.message.reply_text("QR-коды не распознаны на изображении.")
        return
    # multiple QRs
    for obj in decoded:
        try:
            payload = obj.data.decode("utf-8", errors="ignore")
        except Exception:
            payload = obj.data.decode(errors="ignore")
        kind, value = classify_qr_payload(payload)
        if kind == "url":
            await update.message.reply_text(f"🔗 Найдена ссылка в QR: {value}\nПроверяю...")
            await analyze_and_reply(update, context, value)
        elif kind == "tel":
            await update.message.reply_text(f"📞 Найден номер: `{value}`")
        elif kind == "wifi":
            await update.message.reply_text(f"📶 Найден Wi-Fi QR:\n`{value}`")
        elif kind == "vcard":
            await update.message.reply_text(f"👤 Найдена визитка:\n```\n{value}\n```")
        else:
            await update.message.reply_text(f"ℹ️ QR не содержит ссылку — текст:\n`{payload}`")

# Admin commands
async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id if update.effective_user else None
    if uid not in ADMIN_IDS:
        await update.message.reply_text("❌ Вы не админ.")
        return
    async with aiohttp.ClientSession() as session:
        logs = await firebase_get(session, "logs") or {}
        errors = await firebase_get(session, "errors") or {}
        limits = await firebase_get(session, "limits") or {}
    msg = f"📊 Статистика:\nЛогов: {len(logs)}\nОшибок: {len(errors)}\nПользователей: {len(limits)}"
    await update.message.reply_text(msg)

async def cmd_logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id if update.effective_user else None
    if uid not in ADMIN_IDS:
        await update.message.reply_text("❌ Вы не админ.")
        return
    n = 10
    try:
        if context.args:
            n = int(context.args[0])
    except Exception:
        pass
    async with aiohttp.ClientSession() as session:
        logs = await firebase_get(session, "logs") or {}
    # logs is dict with random keys -> sort by timestamp
    entries = sorted((v for v in (logs.values() if isinstance(logs, dict) else [])), key=lambda x: x.get("timestamp",0), reverse=True)[:n]
    text_lines = []
    for e in entries:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("timestamp",0)))
        text_lines.append(f"{t} | user:{e.get('user')} | url:{e.get('url')}")
    if not text_lines:
        await update.message.reply_text("Нет логов.")
    else:
        await update.message.reply_text("Последние логи:\n" + "\n".join(text_lines))

# Error handler
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.exception("Unhandled error: %s", context.error)
    try:
        await log_error(getattr(update, "effective_user", None).id if getattr(update, "effective_user", None) else None,
                        None,
                        str(context.error))
    except Exception:
        pass

async def handle_new_chat_members(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.new_chat_members:
        return

    bot_id = context.bot.id

    for member in update.message.new_chat_members:
        if member.id == bot_id:
            inviter = update.message.from_user

            if not inviter:
                return

            try:
                await context.bot.send_message(
                    chat_id=inviter.id,
                    text=(
                        "👋 Привет! Спасибо, что добавил меня в группу.\n\n"
                        "Чтобы я корректно работал:\n"
                        "• читал сообщения\n"
                        "• проверял ссылки и QR\n"
                        "• не спамил лишним\n\n"
                        "пожалуйста, выдай мне **права администратора** "
                        "(достаточно права читать сообщения).\n\n"
                        "После этого я начну работать автоматически 🛡"
                    )
                )
            except Exception:
                # пользователь мог запретить личные сообщения
                pass

# ---------------------------
# App bootstrap
# ---------------------------
def main():
    if TELEVISION := None:  # placeholder to satisfy lint — no-op
        pass
    if TELEVISION := None:
        pass
    if TELEVISION := None:
        pass

    if TELEVISION is None:
        # warn if keys missing (do not leak)
        if TELEGRAM_TOKEN.startswith("YOUR_") or VIRUSTOTAL_API_KEY.startswith("YOUR_") or URLSCAN_API_KEY.startswith("YOUR_"):
            logger.warning("One or more API keys are placeholders. Set env vars or edit the script to insert keys.")
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CommandHandler("logs", cmd_logs))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_chat_members))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)

    logger.info("[INIT] starting core systems")
    logger.info("   8 8888         `8.`8888.      ,8' b.             8     ,o888888o.      8 888888888o.   8 888888888o       ,o888888o.     8888888 8888888888")
    logger.info("   8 8888          `8.`8888.    ,8'  888o.          8  . 8888     `88.    8 8888    `88.  8 8888    `88.  . 8888     `88.         8 8888")
    logger.info("   8 8888           `8.`8888.  ,8'   Y88888o.       8 ,8 8888       `8b   8 8888     `88  8 8888     `88 ,8 8888       `8b        8 8888")
    logger.info("   8 8888            `8.`8888.,8'    .`Y888888o.    8 88 8888        `8b  8 8888     ,88  8 8888     ,88 88 8888        `8b       8 8888")
    logger.info("   8 8888             `8.`88888'     8o. `Y888888o. 8 88 8888         88  8 8888.   ,88'  8 8888.   ,88' 88 8888         88       8 8888")
    logger.info("   8 8888              `8. 8888      8`Y8o. `Y88888o8 88 8888     `8. 88  8 888888888P'   8 8888888888   88 8888         88       8 8888")
    logger.info("   8 8888               `8 8888      8   `Y8o. `Y8888 88 8888      `8,8P  8 8888`8b       8 8888    `88. 88 8888        ,8P       8 8888")
    logger.info("   8 8888                8 8888      8      `Y8o. `Y8 `8 8888       ;8P   8 8888 `8b.     8 8888      88 `8 8888       ,8P        8 8888")
    logger.info("   8 8888                8 8888      8         `Y8o.`  ` 8888     ,88'8.  8 8888   `8b.   8 8888    ,88'  ` 8888     ,88'         8 8888")
    logger.info("   8 888888888888        8 8888      8            `Yo     `8888888P'  `8. 8 8888     `88. 8 888888888P       `8888888P'           8 8888")

    logger.info("[INFO] bot     : lynqrbot")
    logger.info("[INFO] author  : George Malevanii")
    logger.info("[INFO] year    : 2026")
    logger.info("[INFO] context : regional stage of Information Security olympiad, Krasnodar Krai")
    logger.info("[INFO] team    : blue team")

    logger.info("[OK] secure context established")
    logger.info("[OK] lynqrbot online")
    app.run_polling()

if __name__ == "__main__":
    main()









