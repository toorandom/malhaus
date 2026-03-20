"""
LLM factory: returns a LangChain chat model based on MALHAUS_LLM_PROVIDER.

Supported providers (set MALHAUS_LLM_PROVIDER):
  gemini       — Google Gemini via langchain-google-genai
  openai       — OpenAI via langchain-openai
  azure        — Azure OpenAI via langchain-openai (requires MALHAUS_LLM_ENDPOINT)
  deepseek     — DeepSeek (OpenAI-compatible) via langchain-openai
  claude       — Anthropic Claude via langchain-anthropic
  ollama       — Local Ollama via langchain-ollama (requires MALHAUS_LLM_ENDPOINT)
"""
from typing import Any

import config


def get_llm(model: str) -> Any:
    provider = (config.LLM_PROVIDER or "gemini").lower().strip()
    api_key = config.LLM_API_KEY or ""
    endpoint = config.LLM_ENDPOINT or ""
    timeout = config.LLM_TIMEOUT

    if provider in ("gemini", "google", ""):
        from langchain_google_genai import ChatGoogleGenerativeAI
        from google.genai.types import HarmCategory, HarmBlockThreshold
        # Disable safety filtering for all harm categories — this is a security
        # analysis tool; malware content routinely triggers safety scanners and
        # causes 30+ second delays or empty responses.  All content analysed here
        # is submitted for defensive triage, not generation of harmful material.
        _safety = {
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HARASSMENT:        HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH:       HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        }
        kwargs: dict = {
            "model": model,
            "temperature": 0.1,
            "timeout": timeout,
            "safety_settings": _safety,
        }
        if api_key:
            kwargs["google_api_key"] = api_key
        # Flash/lite models: disable thinking (budget=0) — they respond in ~1s without it.
        # Pro/preview models with mandatory thinking: cap at 8192 tokens so reasoning
        # stays bounded instead of running for minutes unconstrained.
        model_lower = model.lower()
        if "flash" in model_lower or "lite" in model_lower:
            kwargs["thinking_budget"] = 0
        else:
            kwargs["thinking_budget"] = 8192
        return ChatGoogleGenerativeAI(**kwargs)

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        kwargs = {"model": model, "temperature": 0.1, "timeout": timeout}
        if endpoint:
            kwargs["base_url"] = endpoint
        if config.AZURE_USE_ENTRA_ID:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            kwargs["api_key"] = get_bearer_token_provider(
                DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            )
        elif api_key:
            kwargs["api_key"] = api_key
        return ChatOpenAI(**kwargs)

    if provider in ("azure", "azure_openai"):
        from langchain_openai import AzureChatOpenAI
        kwargs = {"azure_deployment": model, "temperature": 0.1, "timeout": timeout}
        if endpoint:
            kwargs["azure_endpoint"] = endpoint
        if config.AZURE_USE_ENTRA_ID:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider
            credential = DefaultAzureCredential()
            kwargs["azure_ad_token_provider"] = get_bearer_token_provider(
                credential, "https://cognitiveservices.azure.com/.default"
            )
        elif api_key:
            kwargs["api_key"] = api_key
        return AzureChatOpenAI(**kwargs)

    if provider == "deepseek":
        from langchain_openai import ChatOpenAI
        kwargs = {
            "model": model,
            "temperature": 0.1,
            "timeout": timeout,
            "base_url": endpoint or "https://api.deepseek.com",
        }
        if api_key:
            kwargs["api_key"] = api_key
        return ChatOpenAI(**kwargs)

    if provider in ("claude", "anthropic"):
        from langchain_anthropic import ChatAnthropic
        kwargs = {"model": model, "temperature": 0.1, "timeout": timeout}
        if api_key:
            kwargs["anthropic_api_key"] = api_key
        return ChatAnthropic(**kwargs)

    if provider == "ollama":
        from langchain_ollama import ChatOllama
        kwargs = {"model": model, "temperature": 0.1, "timeout": timeout}
        if endpoint:
            kwargs["base_url"] = endpoint
        return ChatOllama(**kwargs)

    # Unknown provider — fall back to Gemini and warn
    import sys
    print(f"[llm_factory] WARNING: unknown provider '{provider}', falling back to Gemini", file=sys.stderr)
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(model=model, temperature=0.1)
