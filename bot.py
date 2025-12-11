#!/usr/bin/env python3
"""
Namecheap Domain Checker Bot (FIXED VERSION - SAFE IP LOGGING)
Kiểm tra domain availability và pricing qua Namecheap API
Telegram Bot interface - TIẾNG VIỆT
"""

import os
import sys
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Import checker module
from checker import check_domains

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def log_current_ip():
    """
    Log current outbound IP address (SAFE VERSION WITH EXCEPTION HANDLING)
    This IP needs to be whitelisted on Namecheap API
    """
    try:
        import requests
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        ip = response.json()['ip']
        print("=" * 60)
        print(f"🌐 CURRENT OUTBOUND IP: {ip}")
        print(f"🔑 Add this IP to Namecheap whitelist: {ip}")
        print("=" * 60)
        return ip
    except Exception as e:
        # Fallback: không crash nếu không lấy được IP
        print("=" * 60)
        print(f"⚠️  Could not fetch IP address: {e}")
        print("🔑 Please check your IP manually and whitelist it on Namecheap")
        print("=" * 60)
        return None


# Handler: /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message"""
    welcome_text = (
        "👋 Chào mừng bạn đến với Bot Kiểm Tra Domain Namecheap!\n\n"
        "📋 Hướng dẫn sử dụng:\n"
        "1. Gửi cho tôi file văn bản (.txt) chứa danh sách tên miền\n"
        "2. Mỗi dòng một tên miền (ví dụ: example.com)\n"
        "3. Tôi sẽ kiểm tra tình trạng và giá cả\n"
        "4. Bạn sẽ nhận kết quả dạng file CSV\n\n"
        "💡 Các lệnh:\n"
        "/start - Hiển thị thông báo này\n"
        "/help - Hiển thị trợ giúp\n\n"
        "🚀 Sẵn sàng kiểm tra domain!"
    )
    await update.message.reply_text(welcome_text)


# Handler: /help command
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send help information"""
    help_text = (
        "📖 Trợ giúp - Bot Kiểm Tra Domain Namecheap\n\n"
        "🔍 Tôi có thể làm gì:\n"
        "• Kiểm tra domain còn trống/đã được đăng ký/premium\n"
        "• Lấy giá đăng ký cho domain còn trống\n"
        "• Lấy giá premium cho domain premium\n\n"
        "📝 Định dạng file:\n"
        "• Chỉ file văn bản (.txt)\n"
        "• Mỗi dòng một tên miền\n"
        "• Ví dụ:\n"
        "  example.com\n"
        "  test.net\n"
        "  mysite.org\n\n"
        "⚠️ Lưu ý:\n"
        "• Tối đa 1000 domain mỗi file\n"
        "• Xử lý có thể mất vài phút\n"
        "• Kết quả được lưu dạng file CSV\n\n"
        "❓ Gặp vấn đề? Kiểm tra:\n"
        "1. File có đúng định dạng .txt không\n"
        "2. Mỗi dòng có một domain không\n"
        "3. Không có dòng trống không\n\n"
        "🚀 Gửi file của bạn để bắt đầu!"
    )
    await update.message.reply_text(help_text)


# Handler: Receive document (file upload)
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle uploaded document (domain list file)"""
    document = update.message.document
    
    # Check file type
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text(
            "⚠️ Vui lòng gửi file .txt chứa danh sách tên miền (mỗi dòng một domain)"
        )
        return
    
    # Send processing message
    processing_msg = await update.message.reply_text(
        "⏳ Đang xử lý danh sách domain của bạn...\n"
        "Quá trình này có thể mất vài phút tùy thuộc vào số lượng domain."
    )
    
    try:
        # Download file
        file = await document.get_file()
        input_path = f"/tmp/domains_{update.effective_user.id}.txt"
        await file.download_to_drive(input_path)
        
        # Read domains
        with open(input_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        if not domains:
            await processing_msg.edit_text("⚠️ Không tìm thấy domain nào trong file!")
            return
        
        if len(domains) > 1000:
            await processing_msg.edit_text(
                f"⚠️ Quá nhiều domain ({len(domains)})!\n"
                "Tối đa 1000 domain mỗi lần kiểm tra."
            )
            return
        
        await processing_msg.edit_text(
            f"🔍 Đang kiểm tra {len(domains)} domain...\n"
            f"⏱️ Thời gian ước tính: {len(domains) * 0.5:.0f} giây"
        )
        
        # Get API credentials from environment
        api_user = os.getenv('NAMECHEAP_API_USER')
        username = os.getenv('NAMECHEAP_USERNAME')
        api_key = os.getenv('NAMECHEAP_API_KEY')
        client_ip = os.getenv('NAMECHEAP_CLIENT_IP', '0.0.0.0')
        
        if not all([api_user, username, api_key]):
            await processing_msg.edit_text(
                "❌ Lỗi: Thiếu thông tin API!\n"
                "Vui lòng liên hệ quản trị viên."
            )
            return
        
        # Prepare output paths
        output_csv = f"/tmp/results_{update.effective_user.id}.csv"
        output_json = f"/tmp/results_{update.effective_user.id}.json"
        
        # Run domain check in thread pool (blocking operation)
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            await loop.run_in_executor(
                pool,
                check_domains,
                input_path,
                output_csv,
                api_user,
                username,
                api_key,
                client_ip,
                output_json,
                50,  # batch_size
                False,  # use_sandbox
                20,  # http_timeout
                False  # debug_xml
            )
        
        # Send results
        await processing_msg.edit_text("✅ Kiểm tra hoàn tất! Đang gửi kết quả...")
        
        # Send CSV
        with open(output_csv, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=f"ket_qua_kiem_tra_{update.effective_user.id}.csv",
                caption=f"✅ Đã kiểm tra {len(domains)} domain\n📊 Kết quả dạng CSV"
            )
        
        # Send JSON if exists
        if os.path.exists(output_json):
            with open(output_json, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=f"ket_qua_kiem_tra_{update.effective_user.id}.json",
                    caption="📄 Kết quả dạng JSON"
                )
        
        # Cleanup
        for path in [input_path, output_csv, output_json]:
            if os.path.exists(path):
                os.remove(path)
        
        await processing_msg.edit_text("✅ Xong! Kiểm tra các file bên trên.")
        
    except Exception as e:
        logger.error(f"Error processing document: {e}", exc_info=True)
        await processing_msg.edit_text(
            f"❌ Lỗi xử lý yêu cầu của bạn:\n{str(e)}\n\n"
            "Vui lòng thử lại hoặc liên hệ quản trị viên."
        )


# Handler: Unknown messages
async def handle_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle unknown message types"""
    await update.message.reply_text(
        "❓ Tôi không hiểu tin nhắn đó.\n\n"
        "📋 Vui lòng gửi:\n"
        "• /start - Bắt đầu\n"
        "• /help - Trợ giúp\n"
        "• File .txt chứa danh sách tên miền\n\n"
        "💡 Mẹo: Gửi /help để xem hướng dẫn sử dụng bot"
    )


def main():
    """Main function to run the bot"""
    # Log current IP (SAFE VERSION - won't crash)
    log_current_ip()
    
    # Get bot token
    token = os.getenv('BOT_TOKEN')
    if not token:
        logger.error("❌ BOT_TOKEN not found in environment variables!")
        sys.exit(1)
    
    # Create application
    app = Application.builder().token(token).build()
    
    # Add handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_unknown))
    
    # Start bot
    logger.info("🤖 Bot đang chạy...")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == '__main__':
    main()
