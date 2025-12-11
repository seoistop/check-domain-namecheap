# 🚀 HƯỚNG DẪN DEPLOY LÊN RENDER.COM (ĐƠN GIẢN NHẤT)

## ⚡ TẠI SAO CHỌN RENDER?

✅ **Ưu điểm:**
- Deploy từ GitHub tự động (1 click)
- Có **Static Outbound IP** cố định (đáp ứng yêu cầu Namecheap)
- Không cần cài đặt môi trường phức tạp
- Chạy 24/7 tự động
- Dễ quản lý và xem log

❌ **Nhược điểm:**
- Plan có Static IP: **$7/tháng** (Starter plan)
- Free tier KHÔNG có Static IP → không dùng được

---

## 📋 BƯỚC 1: CHUẨN BỊ CODE TRÊN GITHUB

### 1.1. Tạo Repository GitHub

1. Truy cập: https://github.com
2. Đăng nhập vào tài khoản GitHub
3. Click **New repository** (nút xanh)
4. Điền:
   - **Repository name**: `domain-checker-bot`
   - **Description**: `Namecheap domain checker with Telegram bot`
   - **Public** hoặc **Private** (tuỳ bạn)
   - ❌ **KHÔNG** tick "Add a README file"
5. Click **Create repository**

### 1.2. Upload Code Lên GitHub

**Cách 1: Upload qua Web (Đơn giản nhất)**

1. Sau khi tạo repo, GitHub sẽ hiển thị trang trống
2. Click **uploading an existing file**
3. Kéo thả các file sau vào:
   - `bot.py`
   - `main.py`
   - `checker.py`
   - `config.py`
   - `requirements.txt`
   - `runtime.txt`
   - `README.md`
   - `.gitignore`
4. Click **Commit changes**

**Cách 2: Dùng Git Command Line (Nếu biết Git)**

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/domain-checker-bot.git
git push -u origin main
```

---

## 🌐 BƯỚC 2: DEPLOY LÊN RENDER.COM

### 2.1. Đăng Ký Render

1. Truy cập: https://render.com
2. Click **Get Started**
3. Đăng ký bằng:
   - **GitHub account** (khuyến nghị - dễ kết nối)
   - Hoặc Email

### 2.2. Kết Nối GitHub

- Nếu đăng ký bằng GitHub → tự động kết nối
- Nếu không: Vào **Account Settings** → **Connect GitHub**

### 2.3. Tạo Web Service Mới

1. Từ Dashboard, click **New +** (góc trên bên phải)
2. Chọn **Web Service**
3. Chọn repository: `domain-checker-bot`
4. Click **Connect**

### 2.4. Cấu Hình Service

Điền thông tin:

**Basic Settings:**
- **Name**: `domain-checker-bot` (hoặc tên bạn thích)
- **Region**: Chọn gần bạn nhất
- **Branch**: `main`
- **Root Directory**: để trống
- **Runtime**: `Python 3`

**Build & Deploy:**
- **Build Command**: 
  ```
  pip install -r requirements.txt
  ```
- **Start Command**:
  ```
  python bot.py
  ```

**Instance Type:**
- ⚠️ **QUAN TRỌNG**: Chọn **Starter** ($7/month) hoặc cao hơn
- **KHÔNG chọn Free** (không có Static IP)

### 2.5. Thêm Environment Variables

Scroll xuống phần **Environment Variables**, click **Add Environment Variable**:

Thêm từng biến sau:

| Key | Value | Ghi chú |
|-----|-------|---------|
| `BOT_TOKEN` | `8447157869:AAG...` | Token từ @BotFather |
| `NAMECHEAP_API_USER` | `1fakerlove` | API User từ Namecheap |
| `NAMECHEAP_USERNAME` | `1fakerlove` | Username Namecheap |
| `NAMECHEAP_API_KEY` | `3a08298a9436...` | API Key 32 ký tự |
| `NAMECHEAP_CLIENT_IP` | `0.0.0.0` | Tạm thời để 0.0.0.0, sẽ cập nhật sau |
| `USE_SANDBOX` | `False` | False = production |
| `HTTP_TIMEOUT` | `20` | Timeout 20 giây |
| `BATCH_SIZE` | `50` | Batch size |
| `DEBUG_XML` | `False` | Debug mode |

**Lưu ý**: 
- Thay `BOT_TOKEN`, `NAMECHEAP_API_KEY` bằng giá trị thực của bạn
- `NAMECHEAP_CLIENT_IP` sẽ cập nhật ở bước tiếp theo

### 2.6. Deploy

1. Click **Create Web Service** (nút xanh ở cuối trang)
2. Render sẽ bắt đầu build và deploy
3. Đợi 2-5 phút

---

## 🔑 BƯỚC 3: LẤY STATIC IP VÀ WHITELIST

### 3.1. Bật Static Outbound IP

Sau khi deploy thành công:

1. Vào Dashboard → Chọn service `domain-checker-bot`
2. Click tab **Settings** (bên trái)
3. Scroll xuống phần **Networking**
4. Click **Add Static Outbound IP**
5. Confirm → Đợi vài phút
6. Copy địa chỉ IP tĩnh (vd: `44.123.45.67`)

### 3.2. Whitelist IP Trên Namecheap

1. Đăng nhập Namecheap: https://www.namecheap.com
2. Vào **Profile** → **Tools** → **API Access**
3. Trong phần **Whitelisted IPs**, thêm IP vừa copy
4. Click **Add**
5. Đợi 5-10 phút để cập nhật có hiệu lực

### 3.3. Cập Nhật Environment Variable

1. Quay lại Render Dashboard
2. Vào service `domain-checker-bot`
3. Tab **Environment**
4. Tìm biến `NAMECHEAP_CLIENT_IP`
5. Click **Edit** → Thay `0.0.0.0` bằng **IP tĩnh vừa lấy**
6. Click **Save Changes**
7. Render sẽ tự động deploy lại (đợi 1-2 phút)

---

## ✅ BƯỚC 4: KIỂM TRA VÀ TEST

### 4.1. Kiểm Tra Log

1. Trong Dashboard service, click tab **Logs**
2. Nếu thấy dòng: `🤖 Bot is running...` → Thành công!
3. Nếu có lỗi → Xem phần xử lý lỗi bên dưới

### 4.2. Test Bot

1. Mở Telegram
2. Tìm bot của bạn (tên khi tạo với @BotFather)
3. Gửi `/start`
4. Bot phải phản hồi với hướng dẫn
5. Upload file `.txt` chứa domain để test

**Ví dụ file test (test_domains.txt):**
```
example.com
test.net
mydomain.org
```

---

## 🔄 CẬP NHẬT CODE SAU NÀY

### Cách 1: Push Code Mới Lên GitHub

1. Chỉnh sửa code trên máy local
2. Push lên GitHub:
```bash
git add .
git commit -m "Update code"
git push
```
3. Render sẽ **tự động deploy** khi phát hiện commit mới

### Cách 2: Manual Deploy

1. Vào Render Dashboard → Service
2. Click tab **Manual Deploy** → **Deploy latest commit**

---

## 🐛 XỬ LÝ LỖI THƯỜNG GẶP

### Lỗi 1: "Application failed to start"

**Nguyên nhân**: Thiếu environment variables hoặc sai start command

**Giải pháp**:
1. Kiểm tra tab **Logs** để xem lỗi cụ thể
2. Đảm bảo **Start Command** là: `python bot.py`
3. Kiểm tra tất cả Environment Variables đã điền đầy đủ

### Lỗi 2: "Invalid API Key" / "IP not whitelisted"

**Nguyên nhân**: 
- API Key sai
- IP chưa được whitelist
- IP trong env var chưa cập nhật

**Giải pháp**:
1. Kiểm tra `NAMECHEAP_API_KEY` trong Environment Variables
2. Kiểm tra Static IP đã được thêm vào Namecheap whitelist chưa
3. Đợi 10 phút sau khi whitelist để cập nhật có hiệu lực
4. Kiểm tra `NAMECHEAP_CLIENT_IP` có đúng với Static IP không

### Lỗi 3: "Module not found"

**Nguyên nhân**: File `requirements.txt` bị thiếu hoặc sai

**Giải pháp**:
1. Kiểm tra file `requirements.txt` có trong repo không
2. Nội dung đúng:
```
requests>=2.31.0
python-telegram-bot>=20.0
```
3. Re-deploy

### Lỗi 4: Bot không phản hồi

**Nguyên nhân**: Bot Token sai hoặc service không chạy

**Giải pháp**:
1. Kiểm tra `BOT_TOKEN` trong Environment Variables
2. Kiểm tra Logs có dòng "Bot is running..." không
3. Test lại bot token với @BotFather: `/mybots` → chọn bot → API Token

---

## 💰 CHI PHÍ

### Render Pricing:

| Plan | Giá | Static IP | RAM | CPU |
|------|-----|-----------|-----|-----|
| **Free** | $0 | ❌ Không | 512MB | Shared |
| **Starter** | **$7/tháng** | ✅ **Có** | 512MB | Shared |
| **Standard** | $25/tháng | ✅ Có | 2GB | Dedicated |

👉 **Chọn Starter plan** ($7/tháng) là đủ cho bot này.

### So sánh với các nền tảng khác:

| Nền tảng | Static IP | Giá | Độ khó |
|----------|-----------|-----|--------|
| **Render** | ✅ Có ($7/tháng) | $7 | ⭐⭐ Dễ |
| **Railway** | ❌ Không | $5-10 | ⭐⭐ Dễ |
| **Heroku** | ❌ Không | $7+ | ⭐⭐⭐ Trung bình |
| **DigitalOcean** | ✅ Có | $6/tháng | ⭐⭐⭐⭐ Khó |
| **AWS/Azure** | ✅ Có | ~$10/tháng | ⭐⭐⭐⭐⭐ Rất khó |
| **VPS Windows** | ✅ Có | $10-20/tháng | ⭐⭐⭐⭐⭐ Rất khó |

---

## 🎯 ƯU ĐIỂM CỦA RENDER

✅ Deploy tự động từ GitHub  
✅ Có Static IP (đáp ứng Namecheap)  
✅ Không cần SSH, không cần cài môi trường  
✅ Xem log trực tiếp trên web  
✅ Restart tự động khi crash  
✅ Free SSL certificate  
✅ Hỗ trợ 24/7

---

## 📚 TÀI LIỆU THAM KHẢO

- Render Docs: https://render.com/docs
- Static Outbound IPs: https://render.com/docs/static-outbound-ip-addresses
- Namecheap API: https://www.namecheap.com/support/api/intro/

---

## ✅ CHECKLIST DEPLOY

- [ ] Đã tạo repository trên GitHub
- [ ] Đã upload toàn bộ code (8 files chính)
- [ ] Đã tạo tài khoản Render và kết nối GitHub
- [ ] Đã tạo Web Service với runtime Python
- [ ] Đã chọn **Starter plan** hoặc cao hơn (có Static IP)
- [ ] Đã thêm đầy đủ Environment Variables
- [ ] Đã deploy thành công (xem log "Bot is running...")
- [ ] Đã bật Static Outbound IP
- [ ] Đã whitelist IP trên Namecheap
- [ ] Đã cập nhật `NAMECHEAP_CLIENT_IP` với IP tĩnh
- [ ] Đã test bot trên Telegram thành công

---

## 🆘 HỖ TRỢ

Nếu gặp vấn đề, làm theo thứ tự:

1. **Xem Logs trên Render** → Tab Logs
2. **Kiểm tra Environment Variables** → Đảm bảo đầy đủ và đúng
3. **Kiểm tra Static IP** → Đã bật và whitelist chưa
4. **Test Namecheap API** → Thử gọi API thủ công
5. **Restart service** → Manual Deploy → Deploy latest commit

---

**Chúc bạn deploy thành công! 🎉**

**Render là giải pháp đơn giản nhất cho bot này!**
