FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libjpeg-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .

# Create uploads directory
RUN mkdir -p uploads

# Create www user with restricted permissions
# - No shell access (/bin/false)
# - No home directory creation
# - System user (no login capabilities)
RUN useradd --system --no-create-home --shell /bin/false www

# Create directory structure with root ownership
RUN mkdir -p /home/www

# Generate flag file with restricted permissions
RUN echo "BCTF{Y0U_C4NNOt_F0o1_Y()uR531F}" > /home/www/flag.txt && \
    chown root:root /home/www/flag.txt && \
    chmod 444 /home/www/flag.txt

# Set application permissions
# - www user can only read necessary files (NOT app.py source code)
# - uploads directory is writable by www for functionality
RUN chown -R root:root /app && \
    chmod -R 644 /app && \
    chmod 755 /app && \
    chown www:www /app/uploads && \
    chmod 755 /app/uploads

# Secure app.py by compiling to bytecode and removing source
# Compile Python source to bytecode
RUN python3 -m py_compile /app/app.py

# Move compiled bytecode to protected location
RUN mkdir -p /root/secure && \
    mv /app/__pycache__/app.*.pyc /root/secure/app.pyc && \
    chown root:root /root/secure/app.pyc && \
    chmod 600 /root/secure/app.pyc

# Remove source code completely
RUN rm -f /app/app.py && \
    rm -rf /app/__pycache__

# Create minimal launcher script file
COPY <<EOF /app/secure_launcher.py
#!/usr/bin/env python3
import sys
import types
import os
import pwd
import grp
import marshal

# Load and execute bytecode as root
with open("/root/secure/app.pyc", "rb") as f:
    # Skip the magic number and timestamp (first 16 bytes)
    f.read(16)
    # Load the marshaled code object
    code = marshal.load(f)

# Create module and execute
module = types.ModuleType("app")
exec(code, module.__dict__)

# Drop privileges to www user before starting Flask
www_user = pwd.getpwnam("www")
www_group = grp.getgrnam("www")
os.setgid(www_group.gr_gid)
os.setuid(www_user.pw_uid)

# Start the application
module.app.run(host="0.0.0.0", port=5000, debug=False)
EOF

RUN chown root:root /app/secure_launcher.py && \
    chmod 700 /app/secure_launcher.py

# Ensure www user cannot modify system files
RUN chown -R root:root /home/www && \
    chmod -R 444 /home/www

# Additional security restrictions for www user
# Remove any potential sudo access and lock the account
RUN passwd -l www 2>/dev/null || true

# Remove write permissions from common directories
RUN chmod -R a-w /etc /usr /bin /sbin /lib* 2>/dev/null || true

# Note: We start as root to access secure files, then the app drops to www user internally
# The www user will never have access to the source code

# Expose port
EXPOSE 5000

# Run with additional security options
# Note: These would be applied at container runtime
# --read-only --tmpfs /tmp --tmpfs /var/tmp --security-opt=no-new-privileges

# Run the application via secure launcher
CMD ["python3", "/app/secure_launcher.py"]