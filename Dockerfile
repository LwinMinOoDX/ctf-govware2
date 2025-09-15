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

# Create www user and directory structure
RUN useradd -m -s /bin/bash www
RUN mkdir -p /home/www

# Generate dynamic flag with 16 random hex characters
RUN FLAG_HEX=$(openssl rand -hex 8) && \
    echo "BCTF{0x${FLAG_HEX}}" > /home/www/flag.txt && \
    chown www:www /home/www/flag.txt && \
    chmod 644 /home/www/flag.txt

# Set permissions
RUN chown -R www:www /app
RUN chmod -R 755 /app

# Switch to www user
USER www

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]