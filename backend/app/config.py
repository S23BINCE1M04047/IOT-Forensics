"""Central application settings (override with IFTD_* environment variables)."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IFTD_", env_file=".env", extra="ignore")

    app_name: str = "IoT Forensic Triage Dashboard"
    tool_version: str = "0.2.0-phase2"
    max_upload_mb: int = 200
    upload_dir: Path = BASE_DIR / "uploads"
    database_url: str = f"sqlite:///{(BASE_DIR / 'data' / 'triage.db').as_posix()}"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    insert_batch_size: int = 5000

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()