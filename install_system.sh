#!/usr/bin/env bash
set -e

sudo apt update

sudo apt install -y \
  python3 python3-venv python3-pip \
  build-essential \
  file binutils \
  yara ssdeep radare2 \
  zip unzip curl git \
  jq \
  ltrace strace \
  elfutils \
  nodejs npm \
  p7zip-full \
  binwalk \
  libimage-exiftool-perl

# PE tools (best-effort)
sudo apt install -y pev || true

# JS beautifier (best-effort)
sudo npm install -g js-beautify || true

# Didier Stevens tools
mkdir -p tools
curl -fsSL https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py -o tools/oledump.py
chmod +x tools/oledump.py
curl -fsSL https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py -o tools/pdfid.py
chmod +x tools/pdfid.py
curl -fsSL https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py -o tools/pdf-parser.py
chmod +x tools/pdf-parser.py

echo "System dependencies installed."
