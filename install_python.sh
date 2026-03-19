#!/usr/bin/env bash
set -e

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip

pip install \
  flask gunicorn \
  flask-wtf \
  langchain langchain-core \
  langchain-google-genai \
  langchain-openai \
  langchain-anthropic \
  langchain-ollama \
  pefile \
  flare-floss \
  oletools msoffcrypto-tool \
  LnkParse3 \
  pydantic \
  python-magic \
  requests \
  numpy matplotlib \
  scikit-learn \
  captcha pillow \
  azure-identity

echo "Python dependencies installed."
