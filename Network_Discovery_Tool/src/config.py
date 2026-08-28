from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "NetGuard SMB"
    # Backend SQLite runs in memory or local relative path depending on deployment
    DATABASE_URL: str = "sqlite:///./backend_netguard.db" 
    API_KEYS_MAP: str = "clinic_01:sk_live_12345"
    TRANSIENT_TTL_MINUTES: int = 1440 
    PERSISTENCE_THRESHOLD_MINUTES: int = 2

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()