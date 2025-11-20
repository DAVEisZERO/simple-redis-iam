# STAGE 1: Audit Stage
# We use a temporary image just to check security
FROM python:3.13-slim AS auditor

WORKDIR /audit

# 1. Copy only the requirements
COPY requirements.txt .

# 2. Install pip-audit (It's a dev tool, not for prod)
RUN pip install pip-audit

# 3. RUN THE AUDIT
# -r requirements.txt : Read the file
# --strict            : Fail the build even if the vulnerability is "unfixed"
# --desc              : Show description of the flaw
RUN pip-audit -r requirements.txt --strict --desc

# =========================================
# STAGE 2: Builder / Final Stage
# This only runs if Stage 1 passes!
# =========================================
FROM python:3.13-slim

WORKDIR /app

# 1. Install the packages (Now we know they are safe)
COPY requirements.txt .
COPY ssl_certs\example.com+5-key.pem ssl_certs\example.com+5.pem ssl_certs/ ./ssl_certs/
RUN pip install --no-cache-dir -r requirements.txt

# 2. Copy Code
COPY . .

# 3. Run App
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "ssl_certs/example.com+5-key.pem", "--ssl-certfile", "ssl_certs/example.com+5.pem"]