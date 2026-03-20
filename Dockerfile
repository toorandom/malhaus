FROM debian:bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    build-essential \
    file binutils \
    yara ssdeep radare2 \
    zip unzip curl git \
    jq \
    elfutils \
    nodejs npm \
    p7zip-full \
    binwalk \
    libimage-exiftool-perl \
    osslsigncode \
    firejail \
  && rm -rf /var/lib/apt/lists/*

# Best-effort optional packages (pev not in all mirrors; js-beautify needs npm)
RUN apt-get update && apt-get install -y --no-install-recommends pev; \
    rm -rf /var/lib/apt/lists/* ; true
RUN npm install -g js-beautify --quiet || true

# ── Python venv ───────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN python3 -m venv .venv \
  && .venv/bin/pip install --upgrade pip --quiet \
  && .venv/bin/pip install --quiet -r requirements.txt

# ── Didier Stevens tools ──────────────────────────────────────────────────────
RUN mkdir -p tools \
  && curl -fsSL https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py  -o tools/oledump.py \
  && curl -fsSL https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py    -o tools/pdfid.py \
  && curl -fsSL https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py -o tools/pdf-parser.py \
  && chmod +x tools/oledump.py tools/pdfid.py tools/pdf-parser.py

# ── App source ────────────────────────────────────────────────────────────────
COPY . .

RUN mkdir -p uploads logs extracted

EXPOSE 8000

CMD [".venv/bin/gunicorn", \
     "--workers", "2", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "1800", \
     "--capture-output", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "webapp.app:create_app()"]
