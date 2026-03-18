import os

# a) max size of input (MB)
MAX_UPLOAD_MB = int(os.environ.get("MALHAUS_MAX_UPLOAD_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# c) max requests per IP per hour
MAX_PER_HOUR_PER_IP = int(os.environ.get("MALHAUS_MAX_PER_HOUR", "6"))

# d) max concurrent analyses running at the same time
MAX_CONCURRENT = int(os.environ.get("MALHAUS_MAX_CONCURRENT", "1"))

# b) LLM provider configuration (keep Gemini as default so nothing breaks)
# This file defines how you'd switch later to OpenAI/Claude/DeepSeek/etc.
LLM_PROVIDER = os.environ.get("MALHAUS_LLM_PROVIDER", "")  # gemini|openai|claude|deepseek|...
LLM_ENDPOINT = os.environ.get("MALHAUS_LLM_ENDPOINT", "")        # optional for custom endpoints
LLM_MODEL_STRINGS = os.environ.get("MALHAUS_MODEL_STRINGS", "")  # optional override
LLM_MODEL_VERDICT = os.environ.get("MALHAUS_MODEL_VERDICT", "")  # optional override
LLM_API_KEY = os.environ.get("MALHAUS_LLM_API_KEY", "") # optional; gemini uses GOOGLE_API_KEY today

# Max LLM tool calls per analysis (caps the verdict loop; 0 = verdict-only, no tool calls)
LLM_MAX_TOOL_CALLS = int(os.environ.get("MALHAUS_MAX_TOOL_CALLS", "10"))
LLM_TIMEOUT       = int(os.environ.get("MALHAUS_LLM_TIMEOUT", "30"))   # per-call timeout in seconds

# Show raw LLM prompt/output debug section in report pages (1=show, 0=hide)
LLM_DEBUG_IN_REPORT = int(os.environ.get("MALHAUS_LLM_DEBUG_IN_REPORT", "0"))

# Web UI captcha gate (set MALHAUS_CAPTCHA_ENABLED=0 to disable)
CAPTCHA_ENABLED = os.environ.get("MALHAUS_CAPTCHA_ENABLED", "1") == "1"


# NOTE:
# - Webapp uses MAX_UPLOAD_* and MAX_PER_HOUR_PER_IP now.
# - Your agent currently uses Gemini env vars; no changes required to keep working.
# - Later you can route agent LLM calls by reading these values.
