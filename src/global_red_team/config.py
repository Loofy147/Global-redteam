"""
This module contains the Pydantic settings model for the Red Team Orchestrator.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, ValidationError, validator
from typing import Optional, List
import sys


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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    target_system: str = Field(
        "Production API v2.0", json_schema_extra={"env": "TARGET_SYSTEM"}
    )
    api_url: str = Field("https://api.example.com", json_schema_extra={"env": "API_URL"})
    auth_token: str = Field(..., min_length=20, json_schema_extra={"env": "AUTH_TOKEN"})
    swagger_file: Optional[str] = Field(None, json_schema_extra={"env": "SWAGGER_FILE"})
    max_threads: int = Field(100, json_schema_extra={"env": "MAX_THREADS"})
    timeout: float = Field(5.0, json_schema_extra={"env": "TIMEOUT"})
    rate_limit: int = Field(10, json_schema_extra={"env": "RATE_LIMIT"})
    verbose: bool = Field(True, json_schema_extra={"env": "VERBOSE"})
    static_analysis_path: str = Field(
        "./vulnerable_app", json_schema_extra={"env": "STATIC_ANALYSIS_PATH"}
    )
    fuzzing: FuzzingSettings = FuzzingSettings()

    @validator("auth_token")
    def validate_auth_token(cls, v):
        """Ensure token is not a default/example"""
        if v.startswith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0"):
            raise ValueError(
                "Default token detected! Set a real token in environment"
            )
        return v
