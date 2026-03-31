FROM python:3.10-bookworm

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap wget unzip curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Download pre-compiled ProjectDiscovery tools
# Using -L to follow GitHub redirects to S3 storage
RUN wget -qL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip -q subfinder_2.6.6_linux_amd64.zip subfinder -d /usr/local/bin && \
    rm subfinder_2.6.6_linux_amd64.zip

RUN wget -qL https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip && \
    unzip -q httpx_1.6.0_linux_amd64.zip httpx -d /usr/local/bin && \
    rm httpx_1.6.0_linux_amd64.zip

RUN wget -qL https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip && \
    unzip -q nuclei_3.2.0_linux_amd64.zip nuclei -d /usr/local/bin && \
    rm nuclei_3.2.0_linux_amd64.zip

RUN wget -qL https://github.com/projectdiscovery/katana/releases/download/v1.0.5/katana_1.0.5_linux_amd64.zip && \
    unzip -q katana_1.0.5_linux_amd64.zip katana -d /usr/local/bin && \
    rm katana_1.0.5_linux_amd64.zip

# Verify tools are executable and download Nuclei templates
RUN chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/katana && \
    nuclei -ut

# Set working directory for application
WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

EXPOSE 8000

# Start API bridge
CMD ["python", "api_bridge.py"]
