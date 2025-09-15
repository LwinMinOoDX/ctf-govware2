# Upload Image - SSTI Vulnerability Challenge

This is a CTF challenge featuring a web application with a Server-Side Template Injection (SSTI) vulnerability in EXIF data processing.

## Setup

### Using Docker Compose (Recommended)
```bash
docker-compose up --build
```

### Using Docker directly
```bash
docker build -t upload-image-app .
docker run -p 5000:5000 upload-image-app
```

The application will be available at `http://localhost:5000`

## Vulnerability Details

The application has a Server-Side Template Injection vulnerability in the EXIF data processing. When an image is uploaded, the application extracts EXIF data and renders it using Mako templates without proper sanitization.

## Exploitation

1. Create a malicious image with EXIF data containing Mako template injection payload
2. Upload the image through the web interface
3. The EXIF data will be processed and executed as Mako template code

### Example Exploitation Steps:

1. Use `exiftool` to inject malicious payload into image EXIF data:
```bash
exiftool -Comment='${"__import__(\"os\").popen(\"cat /home/www/flag.txt\").read()}' image.jpg
```

2. Upload the modified image through the web interface
3. The flag will be displayed in the EXIF data section

## Flag Location

The flag is stored in `/home/www/flag.txt` and follows the format `BCTF{0x[16_random_hex_chars]}`

## Security Note

This application is intentionally vulnerable and should only be used for educational purposes in a controlled environment.