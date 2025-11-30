from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List
import os


class RedTeamConfig(BaseSettings):
    """Secure configuration with validation"""

    # Required fields
    api_url: str = Field(..., min_length=1)
    auth_token: str = Field(..., min_length=20)

    # Optional with secure defaults
    max_threads: int = Field(10, ge=1, le=100)
    timeout: float = Field(5.0, ge=1.0, le=30.0)
    rate_limit: int = Field(10, ge=1, le=1000)

    # Database
    database_url: str = Field("findings.db")
    database_pool_size: int = Field(5, ge=1, le=50)

    # Logging
    log_level: str = Field("INFO")
    log_file: Optional[str] = None

    # Security
    verify_ssl: bool = Field(True)
    allowed_hosts: List[str] = Field(default_factory=list)

    # Scanners
    swagger_file: str = Field("swagger.json")
    secondary_user_token: str = Field("placeholder")
    secondary_user_resource_ids: List[int] = Field(default_factory=list)
    fuzz_target_function: str = Field("vulnerable_parser")
    fuzz_max_iterations: int = Field(1000)
    fuzz_timeout: float = Field(0.1)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
