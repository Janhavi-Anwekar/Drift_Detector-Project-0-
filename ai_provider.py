
"""Shared AI provider configuration for Drift Detector."""

import os

import streamlit as st
from google import genai
from google.genai import types


DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


def get_setting(name, default=None):
    """Read a setting from environment variables or Streamlit secrets."""
    value = os.getenv(name)

    if value:
        return value

    try:
        value = st.secrets.get(name)
        if value:
            return value
    except Exception:
        pass

    return default


def get_ai_provider():
    """Return the configured AI provider."""
    provider = get_setting("AI_PROVIDER", "ollama")
    provider = provider.strip().lower()

    if provider not in {"ollama", "gemini"}:
        raise ValueError(
            f"Unsupported AI provider: {provider}"
        )

    return provider


def generate_with_gemini(
    prompt,
    system_instruction="",
    json_mode=False,
):
    """Generate a response using Google's Gemini API."""

    api_key = get_setting("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError("Gemini API key is not configured.")

    model = get_setting(
        "GEMINI_MODEL",
        DEFAULT_GEMINI_MODEL,
    )

    client = genai.Client(api_key=api_key)

    config_options = {
        "temperature": 0.1,
        "max_output_tokens": 400,
    }

    if system_instruction:
        config_options["system_instruction"] = system_instruction

    if json_mode:
        config_options["response_mime_type"] = "application/json"

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(**config_options),
    )

    result = response.text

    if not result or not result.strip():
        raise RuntimeError("Gemini returned an empty response.")

    return result.strip()
