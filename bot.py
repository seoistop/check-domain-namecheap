# -*- coding: utf-8 -*-
import asyncio
import os
from pathlib import Path
from datetime import datetime

from telegram import Update, InputFile
from telegram.constants import ChatAction
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

from config import (
    BOT_TOKEN, ALLOWED_CHAT_ID,
    NAMECHEAP_API_USER, NAMECHEAP_USERNAME, NAMECHEAP_API_KEY, NAMECHEAP_CLIENT_IP,
    USE_SANDBOX, HTTP_TIMEOUT, BATCH_SIZE, DEBUG_XML
)
from checker import run_check_to_csv

TMP_DIR = Path("./tmp")
TMP_DIR.mkdir(exist_ok=True)

HELP_TEXT = (
    "Gửi cho mình 1 file văn bản tên bất kỳ (ví dụ: domains.txt) chứa danh sách domain, mỗi dòng 1 domain.\n"
    "Mình sẽ kiểm tra bằng Namecheap API rồi trả về file kết quả (CSV).\n\n"
    "⚠️ Yêu cầu cấu hình trước trong biến môi trường:\n"
    "- NAMECHEAP_API_USER, NAMECHEAP_USERNAME, NAMECHEAP_API_KEY, NAMECHEAP_CLIENT_IP\n"
    "- (Tuỳ chọn) USE_SANDBOX=1 để dùng sandbox\n"
)

def _check_config_ready() -> bool:
    ok = all([
        BOT_TOKEN,
        NAMECHEAP_API_USER,
        NAMECHEAP_USERNAME,
        NAMECHEAP_API_KEY,
        NAMECHEAP_CLIENT_IP
    ])
    return ok

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if ALLOWED_CHAT_ID and str(update.effective_chat.id) != str(ALLOWED_CHAT_ID):
        return
    await update.message.reply_text("Chào bạn 👋\n" + HELP_TEXT)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if ALLOWED_CHAT_ID and str(update.effective_chat.id) != str(ALLOWED_CHAT_ID):
        return
    await update.message.reply_text(HELP_TEXT)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if ALLOWED_CHAT_ID and str(update.effective_chat.id) != str(ALLOWED_CHAT_ID):
        return

    if not _check_config_ready():
        await update.message.reply_text(
            "⛔ Thiếu cấu hình. Hãy thiết lập biến môi trường:\n"
            "NAMECHEAP_API_USER, NAMECHEAP_USERNAME, NAMECHEAP_API_KEY, NAMECHEAP_CLIENT_IP, BOT_TOKEN"
        )
        return

    doc = update.message.document
    if not doc:
        await update.message.reply_text("Vui lòng gửi 1 file văn bản (.txt) chứa danh sách domain (mỗi dòng 1 domain).")
        return

    # Tải file về
    await update.message.chat.send_action(action=ChatAction.UPLOAD_DOCUMENT)
    file_obj = await context.bot.get_file(doc.file_id)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    in_path  = TMP_DIR / f"in_{ts}.txt"
    out_csv  = TMP_DIR / f"ketqua_{ts}.csv"
    out_json = TMP_DIR / f"ketqua_{ts}.json"  # có thể tắt nếu không cần

    await file_obj.download_to_drive(in_path)

    # Chạy checker (blocking → chạy trong thread pool)
    try:
        await update.message.reply_text("⏳ Đang kiểm tra, vui lòng đợi trong giây lát…")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            run_check_to_csv,
            NAMECHEAP_API_USER, NAMECHEAP_USERNAME, NAMECHEAP_API_KEY, NAMECHEAP_CLIENT_IP,
            in_path, out_csv, out_json,
            USE_SANDBOX, HTTP_TIMEOUT, BATCH_SIZE, DEBUG_XML
        )
    except Exception as e:
        await update.message.reply_text(f"⛔ Lỗi xử lý: {e}")
        try:
            if in_path.exists(): in_path.unlink(missing_ok=True)
        except Exception:
            pass
        return

    # Gửi kết quả về
    try:
        await update.message.reply_document(document=InputFile(out_csv.open("rb"), filename=out_csv.name),
                                            caption="✅ Kết quả CSV")
        # Gửi kèm JSON (tuỳ chọn)
        if out_json.exists():
            await update.message.reply_document(document=InputFile(out_json.open("rb"), filename=out_json.name),
                                                caption="🧾 JSON (tuỳ chọn)")
    finally:
        # Dọn file tạm (có thể giữ lại nếu muốn log)
        try:
            if in_path.exists(): in_path.unlink(missing_ok=True)
            if out_csv.exists(): out_csv.unlink(missing_ok=True)
            if out_json.exists(): out_json.unlink(missing_ok=True)
        except Exception:
            pass

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Nếu người dùng paste domain trực tiếp, hướng dẫn gửi file
    if ALLOWED_CHAT_ID and str(update.effective_chat.id) != str(ALLOWED_CHAT_ID):
        return
    await update.message.reply_text("Vui lòng gửi 1 file .txt chứa danh sách domain (mỗi dòng 1 domain). Gõ /help để xem hướng dẫn.")

def main():
    if not BOT_TOKEN:
        print("⛔ Chưa thiết lập BOT_TOKEN")
        return

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    print("🤖 Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()