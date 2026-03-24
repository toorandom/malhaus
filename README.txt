malhaus — static malware triage platform
Copyright (c) 2026 Eduardo Ruiz Duarte <toorandom@gmail.com>
MIT License — see LICENSE

─────────────────────────────────────────────────────────────────────────────

QUICK START (Docker — recommended)
  See START.md for full instructions.

  cp .env.example .env        # fill in your LLM API key and secret key
  docker compose up -d --build

QUICK START (bare metal / development)
  sudo ./install_system.sh
  sudo ./install_additional.sh
  ./install_python.sh
  cp config.source.example config.source
  nano config.source        # fill in MALHAUS_LLM_API_KEY and MALHAUS_SECRET_KEY
  ./run.sh                  # automatically sources config.source before starting

DOCUMENTATION
  START.md              — Docker deployment guide (new machine, TLS, updates)
  README-API.md         — REST API reference
  README-MCP.md         — MCP server integration
  README-API-KEY-MGNT.md — API key management
  README-CREATE-NEW-TOOL.md — How to add a new analysis tool
