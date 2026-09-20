# 🚀 Panduan Deployment ke Vercel & Google Apps Script Backend

Aplikasi **Financial Journey with You** telah disiapkan dengan arsitektur produksi modern, siap di-deploy secara publik ke **Vercel** dengan keamanan maksimal (*enterprise-grade security*).

---

## 📁 Struktur Folder `versel`

```
versel/
├── Code.gs             # Backend Google Apps Script (PBKDF2-SHA256, HMAC Token, Rate Limiting)
├── api/
│   └── proxy.js        # Vercel Serverless Function (Jembatan aman, IP Rate Limiter & Anti-CORS)
├── vercel.json         # Konfigurasi routing & Security Headers (X-Frame-Options, CSP, dll)
├── index.html          # Frontend Modern (Panel Login Manual, Tanpa Demo, Default Mode Terang)
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
4. **Atomic Rate Limiter (ScriptLock)**:
   - Proteksi brute-force login: 5 kali percobaan gagal akan mengunci akun selama 5 menit secara atomic.
5. **Vercel Serverless Proxy & IP Rate Limiter**:
   - Membatasi 40 request/menit per IP client.
   - Menyembunyikan URL Google Apps Script dari publik.
6. **Anti-Formula Injection (CWE-1236)**:
   - Mencegah injeksi formula spreadsheet (`=`, `+`, `-`, `@`, dll) pada nama penabung, catatan transaksi, dan pengaturan.
7. **Security Headers**:
   - `X-Frame-Options: SAMEORIGIN` / `DEFAULT` (Anti-Clickjacking).
   - `X-Content-Type-Options: nosniff`.
   - `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 🛠️ Langkah 1: Pasang Backend di Google Apps Script

1. Buka **Google Spreadsheet** Anda (atau buat Spreadsheet baru).
2. Di menu atas, klik **Extensions** (Ekstensi) > **Apps Script**.
3. Hapus kode default di file `Code.gs`, lalu **salin dan tempel seluruh isi file `versel/Code.gs`**.
4. Klik ikon **Save** (Simpan 💾).
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

### Opsi A: Deploy via Dashboard Vercel (GitHub)
1. Buat repository baru di GitHub (misal: `keuangan-app`).
2. Masukkan seluruh file di dalam folder `versel/` ke repository tersebut.
3. Buka [vercel.com](https://vercel.com) dan login ke akun Anda.
4. Klik **Add New...** > **Project**, lalu pilih repository GitHub Anda.
5. Pada bagian **Environment Variables**, tambahkan:
   - **Key**: `GAS_API_URL`
   - **Value**: Tempel URL Web App dari Langkah 1 (`https://script.google.com/macros/s/.../exec`)
6. Klik **Deploy**.
7. Dalam hitungan detik, website Anda telah online di domain `https://nama-project.vercel.app`! 🎉

---

### Opsi B: Deploy via Vercel CLI (Terminal)
1. Buka terminal/PowerShell di direktori folder `versel`:
   ```bash
   cd e:\Keuangan_Login\versel
   ```
2. Login ke Vercel (jika belum):
   ```bash
   npx vercel login
   ```
3. Hubungkan project dan set Environment Variable:
   ```bash
   npx vercel
   npx vercel env add GAS_API_URL
   ```
   *(Pilih Production, Preview, Development lalu masukkan URL `/exec`)*
4. Deploy langsung ke Production:
   ```bash
   npx vercel --prod
   ```

---

## 👤 Login Pertama Kali

1. Buka website Vercel yang sudah online.
2. Masukkan kredensial login:
   - **Username**: `admin`
   - **Password**: `admin` *(atau password yang sudah Anda tentukan di sheet `Users`)*
3. Saat pertama kali masuk, sistem akan secara otomatis mengamankan dan mengenkripsi password dengan **PBKDF2-SHA256**.
4. Anda dapat langsung mengubah password melalui menu **Pengaturan > Ganti Password**.

---

## ✨ Status Fitur
- [x] **Panel Login Manual**: Input langsung Username dan Password tanpa modal pilihan/demo.
- [x] **Mode Demo Dihilangkan**: 100% bersih dari mode demo, langsung terhubung ke database.
- [x] **Audit Keamanan Maksimal**: PBKDF2-SHA256, HMAC-SHA256 token, Atomic lockout, IP Rate Limiter, Anti-Formula Injection.
- [x] **Default Mode Terang (Light Mode)**: Desain segar dan bersih saat pertama kali dibuka di mobile maupun desktop.
- [x] **Responsive Mobile**: Header mobile minimalis & rapi, badge target tetap terlihat, tombol menu `☰` di kanan atas.
