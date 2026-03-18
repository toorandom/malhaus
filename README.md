<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/malhaus_logo_dark.png">
    <img src="docs/malhaus_logo_light.png" alt="malhaus" width="480"/>
  </picture>
</p>

Self-hosted **malware static triage platform** powered by LLMs.

Upload a suspicious file or paste a URL — malhaus runs it through a pipeline of static analysis tools (radare2, YARA, strings, objdump, oletools, floss, binwalk, exiftool, optional Ghidra…), feeds the results to an LLM of your choice, and returns a structured verdict with confidence score, key reasons, and full tool output.

**Live demo:** [https://grothendieck.ff2.nl](https://grothendieck.ff2.nl)

![Triage report](docs/screenshot-report.png)

---

## Features

- PE, ELF, Office (OLE/OpenXML), PDF, PowerShell, shell script, JavaScript
- Supports **Gemini, OpenAI, Azure AI Foundry, Claude, DeepSeek**, and any OpenAI-compatible server (Ollama, vLLM, LM Studio)
- REST API with Bearer token authentication and per-key rate limiting
- MCP server — AI agents (Claude, Cursor, Continue…) can call `analyze` natively
- 3D byte-trigram point cloud with HDBSCAN density clusters
- Entropy profile, bigram matrix, compression curve visualizations
- Optional Ghidra headless decompilation (PE/ELF)
- Result cache by SHA-256 — re-submitting the same file is instant
- Captcha-protected web UI; API bypasses captcha with a token

![Mathematical analysis visualizations](docs/screenshot-analysis.png)

---

## Quick start — Docker (recommended)

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Clone
git clone https://github.com/toorandom/malhaus
cd malhaus

# 3. Configure
cp .env.example .env
# edit .env — set MALHAUS_SECRET_KEY and your LLM provider + key

# 4. Point nginx at your domain
sed -i 's/your-domain.com/yourdomain.com/g' nginx/nginx.conf

# 5. Get a TLS certificate
sudo apt install -y certbot
sudo certbot certonly --standalone -d yourdomain.com

# 6. Build and start
docker compose up -d --build
docker compose logs -f
```

The app is now reachable at `https://yourdomain.com`.

See [START.md](START.md) for the full deployment guide including updates, backups, moving to another machine, and troubleshooting.

---

## Quick start — bare metal / development

```bash
sudo ./install_system.sh       # apt packages: radare2, yara, ssdeep, oletools, etc.
sudo ./install_additional.sh   # osslsigncode, captcha/pillow dependencies
./install_python.sh            # creates .venv and installs Python packages

cp config.source.example config.source
nano config.source             # set MALHAUS_LLM_PROVIDER, MALHAUS_LLM_API_KEY, MALHAUS_SECRET_KEY

./run.sh                       # sources config.source and starts gunicorn on 127.0.0.1:8000
```

---

## LLM providers

Set `MALHAUS_LLM_PROVIDER` in `.env` (Docker) or `config.source` (bare metal):

| Provider | Value | Notes |
|----------|-------|-------|
| Google Gemini | `gemini` | Default. `gemini-2.5-flash` / `gemini-2.5-pro` |
| OpenAI | `openai` | `gpt-4o-mini` / `gpt-4o` |
| Azure AI Foundry | `azure` | Set `MALHAUS_LLM_ENDPOINT` to your Azure endpoint |
| Anthropic Claude | `claude` | `claude-haiku-4-5-20251001` / `claude-sonnet-4-6` |
| DeepSeek | `deepseek` | `deepseek-chat` |
| Any OpenAI-compatible | `openai` | Set `MALHAUS_LLM_ENDPOINT` (Ollama, vLLM, LM Studio…) |

See `.env.example` for full configuration examples.

---

## API & MCP

- [REST API reference](README-API.md) — upload files, submit URLs, poll jobs, fetch results
- [MCP server](README-MCP.md) — connect Claude Desktop, Cursor, Continue, or any MCP client
- [API key management](README-API-KEY-MGNT.md) — create, list, revoke keys
- [Adding a new analysis tool](README-CREATE-NEW-TOOL.md) — extend the pipeline

---

## License

MIT — Copyright (c) 2026 Eduardo Ruiz Duarte &lt;toorandom@gmail.com&gt;
