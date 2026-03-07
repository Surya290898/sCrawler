# ------------------------------------------------------------
# Dockerfile – Render / Railway / Azure compatible
# Uses Playwright image and installs Chromium at build time
# ------------------------------------------------------------
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

# Streamlit ports & runtime
ENV STREAMLIT_SERVER_PORT=7860
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_SERVER_ENABLE_CORS=false
ENV STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false

# Workdir
WORKDIR /app

# Install Python deps first (cache-friendly)
COPY requirements.txt .
# IMPORTANT: ensure playwright==1.48.0 in requirements.txt (same as image tag)
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Install the browser(s) that the pinned Playwright expects
# --with-deps pulls OS libs if anything is missing
RUN python -m playwright install --with-deps chromium

# Copy app code
COPY . .

# Health: list browsers (optional debug)
# RUN python - <<'PY'
# import os; print("MSPLAYWRIGHT:", os.listdir("/home/pwuser/.cache/ms-playwright"))
# PY

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=7860", "--server.headless=true"]
