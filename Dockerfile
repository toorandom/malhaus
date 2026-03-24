FROM ubuntu:24.04

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    JAVA_HOME=/usr/lib/jvm/java-21-current \
    PATH="/app/.venv/bin:$PATH"

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python3-dev \
    build-essential \
    file binutils \
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

# radare2 — try apt first, fall back to official .deb from GitHub
RUN apt-get update \
  && apt-get install -y --no-install-recommends radare2 \
  && rm -rf /var/lib/apt/lists/* \
  || ( rm -rf /var/lib/apt/lists/* \
    && ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_${ARCH}.deb" -o /tmp/r2.deb \
    && dpkg -i /tmp/r2.deb \
    && rm /tmp/r2.deb \
    || true )

# Best-effort optional packages
RUN apt-get update && apt-get install -y --no-install-recommends pev; \
    rm -rf /var/lib/apt/lists/* ; true

# JDK 21 — required by Ghidra 11+ (available in Ubuntu 24.04 main repos)
# Creates /usr/lib/jvm/java-21-current symlink so JAVA_HOME works on any arch.
RUN apt-get update \
  && apt-get install -y --no-install-recommends openjdk-21-jdk-headless \
  && ln -sf "$(dirname "$(dirname "$(readlink -f /usr/bin/java)")")" /usr/lib/jvm/java-21-current \
  && rm -rf /var/lib/apt/lists/* \
  || ( rm -rf /var/lib/apt/lists/* ; true )
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
