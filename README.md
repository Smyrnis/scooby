# Scooby C HTTP Server

A lightweight HTTP server written in C for serving static files such as HTML, CSS, JavaScript, images, fonts, and more. Supports correct MIME types including `.ico` files for favicons.

---

## Features

- Serves static files from a directory
- Automatically detects MIME types based on file extensions
- Supports common web file types:
  - HTML, CSS, JavaScript
  - Images: PNG, JPG, GIF, SVG, ICO
  - Fonts: WOFF, WOFF2, TTF, EOT
  - Video: MP4
  - Documents: PDF, JSON
- Handles HTTP GET requests with proper response headers
- Basic error handling (403 Forbidden, 404 Not Found)
- Serves favicon.ico with correct MIME type (`image/x-icon`)

---