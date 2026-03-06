# Base image with Chromium + Playwright already installed
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

# Streamlit needs this
ENV STREAMLIT_SERVER_PORT=7860
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_SERVER_ENABLE_CORS=false
ENV STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false

# Working directory
WORKDIR /app

# Install system packages for Streamlit + Playwright
RUN apt-get update && apt-get install -y \
    libnss3 \
    libgconf-2-4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libxss1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libxcomposite1 \
    libxrandr2 \
    libxdamage1 \
    libgbm1 \
    libpango-1.0-0 \
    libxcursor1 \
    libxi6 \
    && apt-get clean

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy app
COPY . .

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=7860", "--server.headless=true"]
