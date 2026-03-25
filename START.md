# malhaus — getting started

Self-hosted malware static triage platform. Runs as two Docker containers: the
app (Flask + gunicorn) and an nginx reverse proxy that handles HTTPS.

---

## What you need

- A Linux server with a public IP (Debian/Ubuntu recommended)
- A domain name pointed at that server
- Docker + Docker Compose installed
- An API key for your chosen LLM provider (Gemini, OpenAI, Azure AI Foundry, Claude…)

---

## 1 — Install Docker

```bash
curl -fsSL https://get.docker.com | sh
# add your user to the docker group so you don't need sudo every time
sudo usermod -aG docker $USER && newgrp docker
```

---

## 2 — Get the project on your server

**Option A — copy from another machine:**
```bash
scp -r maltriage/ user@your-server:~/
```

**Option B — if you have the image already built (fastest):**
```bash
# on the source machine
docker save malhaus:stable | gzip > malhaus-stable.tar.gz
scp malhaus-stable.tar.gz user@your-server:~/

# on the new server
docker load < malhaus-stable.tar.gz
```

---

## 3 — Configure your domain in nginx

Edit `nginx/nginx.conf` and replace every occurrence of `your-domain.com` with
your actual domain:

```bash
sed -i 's/your-domain.com/malhaus.example.com/g' nginx/nginx.conf
```

---

## 4 — Get a TLS certificate (Let's Encrypt)

```bash
sudo apt install -y certbot
# port 80 must be free (stop nginx if running)
sudo certbot certonly --standalone -d malhaus.example.com
```

Certificates are written to `/etc/letsencrypt/live/malhaus.example.com/` and
mounted read-only into the nginx container automatically.

**Auto-renewal** — certbot installs a systemd timer by default. Verify with:
```bash
sudo systemctl status certbot.timer
```

---

## 5 — Create your .env

```bash
cp .env.example .env
```

Open `.env` and fill in at minimum:

| Variable | What to set |
|----------|-------------|
| `MALHAUS_SECRET_KEY` | Random string — `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `MALHAUS_LLM_PROVIDER` | `gemini` / `openai` / `azure` / `claude` / `deepseek` |
| `MALHAUS_LLM_API_KEY` | Your API key for the chosen provider |

See `.env.example` for all options and provider-specific examples including
**Azure AI Foundry** and **OpenAI-compatible servers** (Ollama, vLLM, LM Studio).

---

## 6 — Build and start

```bash
# build the image and start both containers in the background
docker compose up -d --build

# watch the logs
docker compose logs -f
```

The app is now reachable at `https://your-domain.com`.

> **Note:** `run.sh` and `config.source` are for the bare-metal installation only. If you are using Docker, do not use `run.sh` — the container manages everything. Use the `docker compose` commands below.

---

## Day-to-day operations (Docker)

```bash
# start in the background (normal day-to-day)
docker compose up -d

# stop everything
docker compose down

# restart after a config change (.env, nginx.conf)
docker compose restart

# rebuild and restart after a code change
docker compose up -d --build

# view live logs
docker compose logs -f malhaus
docker compose logs -f nginx

# open a shell inside the running container
docker compose exec malhaus bash
```

The containers are configured with `restart: unless-stopped` — they come back automatically after a server reboot.

---

## Manage API keys (inside the container)

```bash
docker compose exec malhaus .venv/bin/python manage_keys.py create \
  --label "Alice — security team" --rate-limit 30

docker compose exec malhaus .venv/bin/python manage_keys.py list

docker compose exec malhaus .venv/bin/python manage_keys.py revoke <key-id>
```

See `README-API-KEY-MGNT.md` for full key management documentation.

---

## Data persistence

The following are mounted as volumes from the host — they survive container
rebuilds and updates:

| Host path | Container path | Contents |
|-----------|---------------|----------|
| `./maltriage.db` | `/app/maltriage.db` | All analysis results, API keys, cache |
| `./uploads/` | `/app/uploads/` | Temporary uploaded files |
| `./logs/` | `/app/logs/` | Gunicorn logs |

**Back up `maltriage.db` regularly** — it holds your full analysis history.

---

## Updating to a new version

```bash
# pull latest code — preserve your local nginx/nginx.conf (has your real domain + cert paths)
git stash -- nginx/nginx.conf docker-compose.yml
git pull
git stash pop

# rebuild the image and restart (zero-downtime swap takes ~5 seconds)
docker compose up -d --build
```

> **Important:** `nginx/nginx.conf` and `docker-compose.yml` in the repo contain placeholder values (`your-domain.com`, `/etc/letsencrypt`). Your server has these files edited with your real domain and cert paths. Always stash them before pulling, or use `git pull` and resolve conflicts — **never** run `git checkout nginx/nginx.conf` as it will wipe your working config and bring nginx down.
>
> After a pull, if nginx.conf changed upstream you may need to re-apply your domain:
> ```bash
> sed -i 's/your-domain.com/YOUR_ACTUAL_DOMAIN/g' nginx/nginx.conf
> # if using self-signed certs, also fix cert paths (see Quick start step 5b in README)
> docker compose restart nginx
> ```

---

## Moving the image to another machine without rebuilding

```bash
# export on source machine
docker save malhaus:stable | gzip > malhaus-stable.tar.gz

# transfer
scp malhaus-stable.tar.gz user@new-server:~/

# import on new server — then run steps 3–6 above (skip the build flag)
docker load < malhaus-stable.tar.gz
docker compose up -d
```

---

## Troubleshooting

**Container won't start:**
```bash
docker compose logs malhaus
```

**nginx 502 Bad Gateway:**
The app container isn't ready yet or crashed. Check:
```bash
docker compose logs malhaus
docker compose ps
```

**TLS certificate errors:**
Make sure the domain in `nginx/nginx.conf` exactly matches the domain you used
with certbot. Paths must be `/etc/letsencrypt/live/<your-domain>/`.

**Firejail sandbox errors inside the container:**
The app uses firejail to sandbox analysis tools. If you see seccomp or
namespace errors, ensure `docker-compose.yml` has the `cap_add` entries
(`SYS_PTRACE`, `NET_ADMIN`) and `no-new-privileges:false`.

**Analysis always fails / LLM errors:**
Check that `MALHAUS_LLM_PROVIDER` and `MALHAUS_LLM_API_KEY` are set correctly
in `.env`. Test connectivity from inside the container:
```bash
docker compose exec malhaus curl -s https://api.openai.com
```

---

## Alternative: bare-metal / development (no Docker)

Use this if you want to run directly on the host without containers.

```bash
sudo ./install_system.sh       # apt packages: radare2, yara, ssdeep, etc.
sudo ./install_additional.sh   # osslsigncode, certbot dependencies
./install_python.sh            # creates .venv and installs Python packages
```

**Configure `config.source` before starting:**

```bash
nano config.source
```

The file is pre-populated with placeholders. Fill in at minimum:

| Variable | What to set |
|----------|-------------|
| `MALHAUS_SECRET_KEY` | Random string — `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `MALHAUS_LLM_PROVIDER` | `gemini` / `openai` / `azure` / `claude` / `deepseek` |
| `MALHAUS_LLM_API_KEY` | Your API key |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Same as above if using Gemini |

Then start the app — `run.sh` sources `config.source` automatically:

```bash
./run.sh
```

The app listens on `http://127.0.0.1:8000`. Put nginx or caddy in front for HTTPS.
