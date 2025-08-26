FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    git \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Verify installations
RUN node --version && npm --version && npx --version

# Set working directory
WORKDIR /workspace

RUN pip install --upgrade pip && \
    pip install google-adk python-dotenv

# Expose port
EXPOSE 8000

CMD ["bash", "-c", "echo '🚀 Starting ADK Web UI...' && adk web --host 0.0.0.0 --port 8000"]
