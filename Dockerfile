# =========================
#       AutoVol Docker
# =========================
FROM python:3.11-slim


LABEL maintainer="osama.ghozlan@gmail.com"
LABEL description="AutoVol: Volatility 3-based memory forensics runner with TUI/CLI mode"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install base system utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git curl unzip build-essential \
    libffi-dev libssl-dev libmagic-dev \
    libpython3-dev python3-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup Volatility 3
RUN git clone https://github.com/volatilityfoundation/volatility3 /opt/volatility3

# Install volatility3 in editable mode with full extras
RUN pip install -e "/opt/volatility3[full]"

# Use Volatility3 via vol.py
ENV PYTHONPATH="$PYTHONPATH:/opt/volatility3"

ARG DOWNLOAD_SYMBOLS=false

# Optional download of symbols for Windows, Linux, and macOS
RUN if [ "$DOWNLOAD_SYMBOLS" = "true" ]; then \
    echo "📦 Downloading Volatility 3 symbols..." && \
    mkdir -p /opt/volatility3/symbols && cd /opt/volatility3/symbols && \
    for os in windows mac linux; do \
        echo "📥 Downloading $os symbols..." && \
        curl -s -O https://downloads.volatilityfoundation.org/volatility3/symbols/${os}.zip && \
        unzip -q ${os}.zip && rm ${os}.zip; \
    done; \
    else echo "⚠️ Skipping symbol download (--build-arg DOWNLOAD_SYMBOLS=true)"; fi

# Set working dir for AutoVol
WORKDIR /app

# Copy your app into container
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default to show help
CMD ["python", "autovol.py", "-h"]
