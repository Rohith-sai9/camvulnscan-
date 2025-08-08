FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
RUN pip install -e .

# Default command (help)
CMD ["netsec-audit", "--help"]
