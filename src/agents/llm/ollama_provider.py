
import os
import requests

from src.agents.llm.base import LLMProvider


class OllamaProvider(LLMProvider):
    """LLM provider using a locally running Ollama server."""

    def __init__(
        self,
        model: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434",
        timeout: int | None = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        if timeout is None:
            self.timeout = int(os.getenv("OLLAMA_TIMEOUT", "30"))
        else:
            self.timeout = timeout

    def is_available(self) -> bool:
        """Fast check to see if Ollama is running and responsive."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str) -> str:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Prompt must be a non-empty string.")

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                    },
                },
                timeout=self.timeout,
            )

            response.raise_for_status()
            result = response.json()

            generated_text = result.get("response", "").strip()

            if not generated_text:
                raise RuntimeError("Ollama returned an empty response.")

            return generated_text

        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError(
                "Cannot connect to Ollama. Make sure Ollama is running."
            ) from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError("Ollama request timed out.") from exc

        except requests.exceptions.HTTPError as exc:
            raise RuntimeError(
                f"Ollama HTTP error: {exc}"
            ) from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"Ollama request failed: {exc}"
            ) from exc
