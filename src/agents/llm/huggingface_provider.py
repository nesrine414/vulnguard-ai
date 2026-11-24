"""LLM provider Cloud ultra-rapide (Alternative officielle à Bedrock)."""

import os
from src.agents.llm.base import LLMProvider


class CloudLLMProvider(LLMProvider):
    """Fournisseur LLM Cloud Llama 3 via le SDK Groq officiel."""

    def __init__(
        self,
        api_token: str | None = None,
        model: str = "openai/gpt-oss-20b",
    ):
        self.api_token = api_token or os.getenv("GROQ_API_TOKEN")
        self.model = model

    def is_available(self) -> bool:
        """Vérifie si le token est configuré."""
        return bool(self.api_token and self.api_token.startswith("gsk_"))

    def generate(self, prompt: str) -> str:
        """Génère l'explication en une fraction de seconde dans le Cloud."""
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
                    "content": "You are a cybersecurity expert assistant analyzing vulnerabilities.",
                },
                {"role": "user", "content": prompt},
            ],
            model=self.model,
            temperature=0.2,
            max_tokens=300,
        )

        return chat_completion.choices[0].message.content.strip()


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    print("Test du provider Cloud Llama 3.1 avec le SDK officiel...")
    llm = CloudLLMProvider()
    if llm.is_available():
        res = llm.generate("Explain in two concise sentences what is a CVE vulnerability.")
        print("\n✅ Réponse reçue en direct du Cloud :\n")
        print(res)
    else:
        print("⚠️ GROQ_API_TOKEN non trouvé dans .env")