# Instalasi & Penggunaan di Termux

## 1. Persiapan Termux

Disarankan menggunakan Termux versi terbaru dari sumber resmi.

Update package:

```bash
pkg update && pkg upgrade -y
```

Install dependency dasar:

```bash
pkg install python git curl wget -y
```

Cek versi Python:

```bash
python --version
```

---

## 2. Clone Repository

Clone repository:

```bash
git clone https://github.com/aseprizkir/ai.git
```

Masuk ke directory:

```bash
cd ai
```

Jika file `ai.py` berada di directory tersebut, cek dengan:

```bash
ls
```

---

## 3. Install Python Dependencies

Install library yang dibutuhkan:

```bash
pip install openai rich ddgs shodan
```

Jika Termux menolak instalasi package karena environment Python, gunakan:

```bash
pip install openai rich ddgs shodan --break-system-packages
```

Tool menggunakan OpenAI-compatible API untuk berkomunikasi dengan model AI.

---

## 4. Konfigurasi API

Sebelum menjalankan tool, periksa bagian konfigurasi pada `ai.py`.

Contoh:

```python
client = OpenAI(
    api_key="YOUR_API_KEY",
    base_url="YOUR_API_BASE_URL",
)
```

Sesuaikan:

```text
YOUR_API_KEY
YOUR_API_BASE_URL
```

dengan provider/model yang digunakan.

> Jangan commit API key asli ke GitHub. Gunakan environment variable atau file konfigurasi lokal.

---

## 5. Menjalankan AI CLI

Mode normal:

```bash
python ai.py
```

Pada mode normal, tool akan meminta konfirmasi sebelum menjalankan `run_shell` atau melakukan `write_file`.

Contohnya:

```text
🛠 AI mau jalanin command

nmap example.com

Approve? [y/N]:
```

Masukkan:

```text
y
```

untuk menjalankan command.

---

## 6. Mode YOLO

Tool juga menyediakan mode `--yolo`:

```bash
python ai.py --yolo
```

Mode ini otomatis menyetujui operasi `run_shell` dan `write_file` tanpa meminta konfirmasi.

**Gunakan mode ini hanya jika kamu memahami command yang mungkin dijalankan oleh AI.**

---

# Fitur Utama

## Shell Command

AI dapat menjalankan command melalui:

```text
run_shell
```

Contohnya:

```text
nmap
curl
nuclei
httpx
ffuf
```

Tool `run_shell` memang dirancang untuk menjalankan command shell pada mesin tempat AI dijalankan.

---

## Membaca File

AI dapat membaca file menggunakan:

```text
read_file
```

Contoh:

```text
Baca file config.py
```

---

## Menulis File

AI dapat membuat atau mengubah file menggunakan:

```text
write_file
```

Contoh:

```text
Buat report.md berdasarkan hasil scanning sebelumnya
```

Operasi write akan meminta konfirmasi pada mode normal.

---

## Web Search

AI memiliki fitur pencarian web melalui:

```text
search_web
```

Contoh:

```text
Cari CVE terbaru untuk Apache HTTP Server
```

Tool mendukung pencarian web dan news serta beberapa operator pencarian seperti:

```text
site:
inurl:
intitle:
filetype:
intext:
```

---

## Dorking

Gunakan fitur:

```text
dork_web
```

untuk melakukan pencarian berdasarkan template.

Template yang tersedia antara lain:

```text
exposed_files
admin_panels
login_pages
subdomains
open_dirs
juicy_files
git_exposed
api_keys
cameras
sqli_prone
error_pages
wp_vulns
phpmyadmin
s3_buckets
custom
```

Contoh penggunaan melalui AI:

```text
Lakukan recon dorking untuk example.com
```

---

## Shodan

Tool juga menyediakan integrasi Shodan melalui:

```text
shodan_search
```

Tersedia tiga mode:

```text
host
search
count
```

Contoh:

```text
Cek informasi Shodan untuk IP 1.2.3.4
```

atau:

```text
Cari service Apache yang terekspos menggunakan Shodan
```

Untuk fitur Shodan, API key perlu dikonfigurasi terlebih dahulu.

---

# Slash Commands

Di dalam CLI tersedia beberapa command:

```text
/help
```

Menampilkan daftar bantuan.

```text
/clear
```

Menghapus history percakapan saat ini.

```text
/save
```

Menyimpan session.

```text
/save nama-session
```

Menyimpan session dengan nama tertentu.

```text
/load nama-session
```

Memuat session sebelumnya.

```text
/sessions
```

Menampilkan session yang tersimpan.

```text
/context target=example.com scope=*.example.com
```

Menambahkan informasi target ke konteks AI.

Command tersebut tersedia langsung di dalam program.

---

# Contoh Penggunaan

Setelah menjalankan:

```bash
python ai.py
```

kamu bisa memberikan instruksi seperti:

```text
> Analisis example.com secara pasif
```

atau:

```text
> Cek teknologi yang digunakan oleh example.com
```

atau:

```text
> Cari CVE terbaru yang berkaitan dengan teknologi yang ditemukan
```

Untuk target yang memang kamu miliki atau memiliki izin untuk diuji:

```text
> Lakukan security assessment terhadap target lab saya dan jelaskan temuannya
```

AI kemudian dapat menentukan apakah perlu menggunakan tool seperti `run_shell`, `search_web`, atau tool lainnya. Sistemnya menggunakan pola tool-call loop: AI memilih tool → tool dijalankan → hasil dikembalikan ke AI → AI melanjutkan proses.

---

# Catatan Termux

Beberapa tool eksternal seperti `nmap`, `nuclei`, `httpx`, atau `ffuf` harus tersedia di environment Termux jika ingin digunakan melalui `run_shell`.

Contoh instalasi Nmap:

```bash
pkg install nmap -y
```

Kemudian cek:

```bash
nmap --version
```

Untuk tool lainnya, install sesuai kebutuhan dan pastikan executable-nya tersedia di `$PATH`.

---

# Keamanan

Tool ini memiliki kemampuan menjalankan command shell pada perangkat pengguna. Karena itu:

* Gunakan hanya pada sistem yang kamu miliki atau memiliki izin untuk menguji.
* Review command sebelum memberikan approval.
* Hindari penggunaan `--yolo` jika tidak memahami command yang mungkin dijalankan.
* Jangan memasukkan API key asli ke repository publik.
* Jangan menjalankan command yang diberikan AI secara otomatis pada sistem produksi tanpa review.

Mode normal secara default memang menyediakan konfirmasi sebelum `run_shell` dan `write_file` dijalankan.
