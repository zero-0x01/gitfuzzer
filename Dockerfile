FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create app directory and user
RUN groupadd -r gitfuzzer && useradd -r -g gitfuzzer gitfuzzer
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY gitfuzzer/ ./gitfuzzer/
COPY config.example.yml ./config.yml
COPY LICENSE README.md CHANGELOG.md ./

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/reports && \
    chown -R gitfuzzer:gitfuzzer /app

# Switch to non-root user
USER gitfuzzer

# Set the Python path
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import gitfuzzer; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "gitfuzzer.cli"]
CMD ["--help"]
