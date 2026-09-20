# 🚀 Panduan Deployment ke Vercel & Google Apps Script Backend

Aplikasi **Financial Journey with You** telah disiapkan dengan arsitektur produksi modern, siap di-deploy secara publik ke **Vercel** dengan keamanan maksimal (*enterprise-grade security*).

---

## 📁 Struktur Folder `versel`

```
versel/
├── Code.gs             # Backend Google Apps Script (PBKDF2-SHA256, HMAC Token, Rate Limiting, Mode Demo Read-Only)
├── api/
│   └── proxy.js        # Vercel Serverless Function (Jembatan aman, IP Rate Limiter & Anti-CORS)
├── vercel.json         # Konfigurasi routing & Security Headers (X-Frame-Options, CSP, dll)
├── index.html          # Frontend Modern (Panel Pilihan: User Demo & Login Admin Manual, Default Mode Terang)
├── package.json        # Konfigurasi Node.js project
└── README.md           # Panduan Deployment ini
```

---

## 🔒 Fitur Keamanan Maksimal (Audit Security)

1. **PBKDF2-SHA256 Salted Password Hashing**:
   - Password disimpan dengan multi-round key stretching (2000 rounds + 32 karakter unique salt).
   - Dilengkapi *Seamless Auto-Migration* (password lama di Spreadsheet otomatis di-hash saat login pertama).
2. **HMAC-SHA256 Session Token (30 Menit TTL)**:
   - Token ditandatangani secara kriptografis dengan secret key acak yang dirotasi aman.
3. **Dual-Layer Fail-Secure Token Revocation**:
   - Saat pengguna menekan *Keluar (Logout)*, token langsung dicabut di `CacheService` dan `ScriptProperties`.
4. **Role-Based Server Authorization**:
   - **Mode Demo**: Token bertipe `demo` hanya memiliki hak akses baca (*View Only*). Operasi penambahan, pengeditan, atau penghapusan transaksi strictly ditolak di server dengan error `FORBIDDEN`.
   - **Mode Admin**: Token bertipe `admin` memiliki hak penuh untuk mencatat dan mengelola data.
5. **Atomic Rate Limiter (ScriptLock)**:
   - Proteksi brute-force login: 5 kali percobaan gagal akan mengunci akun selama 5 menit secara atomic.
6. **Vercel Serverless Proxy & IP Rate Limiter**:
   - Membatasi 40 request/menit per IP client.
   - Menyembunyikan URL Google Apps Script dari publik.
7. **Anti-Formula Injection (CWE-1236)**:
   - Mencegah injeksi formula spreadsheet (`=`, `+`, `-`, `@`, dll) pada nama penabung, catatan transaksi, dan pengaturan.
8. **Security Headers**:
   - `X-Frame-Options: SAMEORIGIN` / `DEFAULT` (Anti-Clickjacking).
   - `X-Content-Type-Options: nosniff`.
   - `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 🛠️ Langkah 1: Pasang Backend di Google Apps Script

1. Buka **Google Spreadsheet** Anda.
2. Di menu atas, klik **Extensions** (Ekstensi) > **Apps Script**.
3. Hapus kode default di file `Code.gs`, lalu **salin dan tempel seluruh isi file `versel/Code.gs`**.
4. Klik ikon **Save** (Simpan 💾 / `Ctrl + S`).
5. Klik tombol biru **Deploy** (Terapkan) di pojok kanan atas > **New deployment** (Penerapan baru).
6. Klik ikon gerigi ⚙️ di sebelah *Select type* > pilih **Web App**.
7. Isi konfigurasi sebagai berikut:
   - **Description**: `Production Vercel Backend`
   - **Execute as**: `Me` (*Email Anda*)
   - **Who has access**: `Anyone` (*Siapa saja*)
8. Klik **Deploy** dan berikan izin (*Authorize access*) dengan memilih akun Google Anda.
9. **Salin Web App URL** yang diberikan (berakhiran `/exec`).  
   *Contoh format: `https://script.google.com/macros/s/AKfycbx.../exec`*

---

## ☁️ Langkah 2: Deploy ke Vercel

1. Buka [vercel.com](https://vercel.com) dan buat project baru dari repository GitHub Anda.
2. Di layar **New Project**:
   - **Root Directory**: Klik `Edit` dan pilih/ketik `versel`.
   - **Application Preset**: Biarkan `Other`.
   - **Environment Variables**:
     - **Key**: `GAS_API_URL`
     - **Value**: Tempel URL Web App dari Langkah 1 (`https://script.google.com/macros/s/.../exec`)
3. Klik tombol **Deploy**.
4. Dalam beberapa detik, website Anda telah online di domain `https://nama-project.vercel.app`! 🎉

---

## 👤 Mode Masuk Aplikasi

1. **Masuk User Demo (Lihat Saja)**:
   - Klik satu tombol untuk langsung masuk tanpa password.
   - Mengambil data **asli dan live** langsung dari Google Spreadsheet.
   - Seluruh form pencatatan dan pengaturan berstatus terkunci (*View Only*).
2. **Login Admin (Input Manual)**:
   - Masukkan **Username** dan **Password** Admin (default awal: `admin` / `admin`).
   - Akses penuh untuk menambah, mengedit, menghapus transaksi, serta mengatur profil dan target.
