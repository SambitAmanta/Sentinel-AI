"""Application configuration settings."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "SentinelAI"
    VERSION: str = "0.1.0"
    DEBUG: bool = True
    
    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    ROOT_DIR: Path = BASE_DIR.parent
    SCRATCH_DIR: Path = BASE_DIR / "scratch"
    
    # Local SLM Configuration (RTX 5050 8GB)
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    OLLAMA_TEMPERATURE: float = 0.1
    
    # Mock / Fallback Mode (allows local testing without Ollama running)
    ENABLE_MOCK_LLM_FALLBACK: bool = True
    
    # Agent Guardrails
    MAX_SELF_HEAL_ITERATIONS: int = 3
    SANDBOX_TIMEOUT_SECONDS: int = 15
    MAX_FILES_PER_AUDIT: int = 30

    model_config = {
        "env_file": ".env",
        "extra": "ignore",
    }

settings = Settings()
