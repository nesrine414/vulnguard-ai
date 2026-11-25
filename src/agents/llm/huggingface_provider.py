"""LLM provider Cloud ultra-rapide (Alternative officielle à Bedrock)."""

import os
from src.agents.llm.base import LLMProvider


class CloudLLMProvider(LLMProvider):
    """Fournisseur LLM Cloud via le SDK Groq officiel."""

    def __init__(
        self,
        api_token: str | None = None,
        # Modèle de chat ultra-fiable disponible sur ton compte
        model: str = "qwen/qwen3.8-27b",
    ):
        self.api_token = api_token or os.getenv("GROQ_API_TOKEN")
        self.model = model

    def is_available(self) -> bool:
        """Vérifie si le token est configuré."""
        return bool(self.api_token and self.api_token.startswith("gsk_"))

    def generate(self, prompt: str) -> str:
        """Génère l'explication complète dans le Cloud."""
        if not self.is_available():
            raise RuntimeError(
                "GROQ_API_TOKEN manquant ou invalide dans le fichier .env."
            )

        from groq import Groq

        client = Groq(api_key=self.api_token)
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert assistant analyzing vulnerabilities. Follow the exact requested structure and report verified facts only.",
                },
                {"role": "user", "content": prompt},
            ],
            model=self.model,
            temperature=0.2,
            # On donne 1024 tokens pour que les 6 sections soient complètes
            max_tokens=1024,
        )

        message = chat_completion.choices[0].message
        content = getattr(message, "content", "") or ""
        
        # Sécurité de fallback si le modèle a renvoyé dans un champ de raisonnement
        if not content and hasattr(message, "reasoning"):
            content = getattr(message, "reasoning", "") or ""

        return str(content).strip()