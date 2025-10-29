"""
This module contains the Pydantic settings model for the Red Team Orchestrator.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List


class FuzzingSettings(BaseSettings):
    """Settings for the fuzzing module."""

    enabled: bool = True
    target_function: str = "vulnerable_parser"
    max_iterations: int = 1000
    timeout: float = 1.0
    seeds: List[str] = ["some initial data"]
    mutation_strategies: List[str] = [
        "bit_flip",
        "byte_flip",
        "arithmetic",
        "interesting_values",
        "dictionary",
        "havoc",
        "splice",
    ]


class Settings(BaseSettings):
    """Settings for the Red Team Orchestrator."""

    target_system: str = Field("Production API v2.0", env="TARGET_SYSTEM")
    api_url: str = Field("https://api.example.com", env="API_URL")
    auth_token: str = Field(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.test",
        env="AUTH_TOKEN",
    )
    swagger_file: Optional[str] = Field(None, env="SWAGGER_FILE")
    max_threads: int = Field(100, env="MAX_THREADS")
    timeout: float = Field(5.0, env="TIMEOUT")
    verbose: bool = Field(True, env="VERBOSE")
    fuzzing: FuzzingSettings = FuzzingSettings()

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
