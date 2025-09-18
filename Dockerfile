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
# - www user can only read application files
# - uploads directory is writable by www for functionality
RUN chown -R root:root /app && \
    chmod -R 644 /app && \
    chmod 755 /app && \
    chown www:www /app/uploads && \
    chmod 755 /app/uploads

# Make app.py executable for Python
RUN chmod 644 /app/app.py

# Ensure www user cannot modify system files
RUN chown -R root:root /home/www && \
    chmod -R 444 /home/www

# Additional security restrictions for www user
# Remove any potential sudo access and lock the account
RUN passwd -l www 2>/dev/null || true

# Remove write permissions from common directories
RUN chmod -R a-w /etc /usr /bin /sbin /lib* 2>/dev/null || true

# Switch to www user (now with restricted permissions)
USER www

# Expose port
EXPOSE 5000

# Run with additional security options
# Note: These would be applied at container runtime
# --read-only --tmpfs /tmp --tmpfs /var/tmp --security-opt=no-new-privileges

# Run the application
CMD ["python", "app.py"]