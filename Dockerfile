# Multi-stage extraction of official ProjectDiscovery security binaries
FROM projectdiscovery/subfinder:latest AS subfinder_bin
FROM projectdiscovery/naabu:latest AS naabu_bin
FROM projectdiscovery/httpx:latest AS httpx_bin
FROM projectdiscovery/nuclei:latest AS nuclei_bin

# Main Python environment
FROM python:3.11-slim

# Install system dependencies needed for networking, DNS, packet capture, and Alpine-musl binary compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libpcap-dev \
    dnsutils \
    musl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled, official security tool binaries into PATH
COPY --from=subfinder_bin /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=naabu_bin /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=httpx_bin /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PREFER_LOCAL_TOOLS=true

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and templates
COPY . .

# Expose web application port
EXPOSE 8000

# Initialize database schema and start server
CMD ["sh", "-c", "python init_db.py && uvicorn main:app --host 0.0.0.0 --port 8000"]
