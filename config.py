# -*- coding: utf-8 -*-
import os

# Telegram - Lấy từ biến môi trường (Environment Variables trên Render)
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ALLOWED_CHAT_ID = os.getenv("ALLOWED_CHAT_ID", None)

# Namecheap - Lấy từ biến môi trường
NAMECHEAP_API_USER = os.getenv("NAMECHEAP_API_USER", "")
NAMECHEAP_USERNAME = os.getenv("NAMECHEAP_USERNAME", "")
NAMECHEAP_API_KEY = os.getenv("NAMECHEAP_API_KEY", "")
NAMECHEAP_CLIENT_IP = os.getenv("NAMECHEAP_CLIENT_IP", "")

# Tuỳ chọn
USE_SANDBOX = os.getenv("USE_SANDBOX", "False").lower() == "true"
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "20"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
DEBUG_XML = os.getenv("DEBUG_XML", "False").lower() == "true"
