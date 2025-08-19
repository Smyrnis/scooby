# Scooby C HTTP Server

A lightweight HTTP/HTTPS server written in C for serving static files and executing PHP via `php-cgi`.  
Designed as a learning project, but capable of running simple websites with both static and dynamic content.

---

## ✨ Features

- **Static file serving**
  - Serves files from a configurable root directory (`./www` by default)
  - Detects MIME types based on file extensions
  - Supports HTML, CSS, JS, images, fonts, video, JSON, PDF, and more

- **Dynamic PHP execution**
  - Runs `.php` files through `php-cgi`
  - Supports GET and POST parameters
  - Passes environment variables to PHP scripts (like a CGI server)
  - Example: `scooby.php` demonstrates the use of a .php file.

- **HTTPS support**
  - Built-in SSL/TLS support via OpenSSL
  - Provides both HTTP (8080) and HTTPS (8443) endpoints
  - Uses self-signed certificates (suitable for development)

- **Thread pool architecture**
  - Handles multiple client requests concurrently
  - Limits queue size for stability

- **Error handling**
  - Returns appropriate status codes:
    - `400 Bad Request`
    - `403 Forbidden`
    - `404 Not Found`
    - `405 Method Not Allowed`
    - `431 Request Header Fields Too Large`
    - `500 Internal Server Error`

---

## 🔧 Requirements

- GCC / Clang (Linux) or MinGW (Windows)
- OpenSSL library (`libssl-dev` on Linux)
- `php-cgi` installed (for PHP support)
  - Linux: `sudo apt install php-cgi`
  - Windows: download PHP binaries and ensure `php-cgi.exe` is in PATH

---

## 🚀 Build & Run

### Linux / WSL
```bash
make
./server
