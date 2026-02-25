#!/usr/bin/env python3

import os
from pathlib import Path
import click
from dotenv import load_dotenv
from typing import Optional
from .types.config import AIConfig, ResearchConfig, TechSpecConfig, LogConfig


class Config:
    aiConfig: AIConfig
    techSpecConfig: TechSpecConfig
    logConfig: LogConfig
    researchConfig: ResearchConfig


    def __init__(self, env_file: Optional[str] = None):
        self._load_env_files(env_file)
        self._load_config()

    def _load_env_files(self, env_file: Optional[str] = None) -> None:
        """Load environment variables with proper precedence.
        
        Precedence order:
        1. Explicitly passed env_file parameter
        2. .env file in current working directory (where command is run from)
        3. .env file in grace-cli directory
        4. .env file in root directory (parent of grace-cli)
        """
        # If env_file is explicitly provided, use it
        if env_file is not None:
            if Path(env_file).exists():
                load_dotenv(env_file)
                return
            else:
                click.echo(f"Warning: Specified env file '{env_file}' not found.")
        
        # Look for .env files in order of precedence
        current_dir = Path.cwd()  # Current working directory where command is run
        grace_cli_root = Path(__file__).parent.parent  # grace-cli directory
        project_root = grace_cli_root.parent  # parent of grace-cli directory
        
        env_locations = [
            current_dir / ".env",     # .env in current working directory
            grace_cli_root / ".env",  # grace-cli/.env
            project_root / ".env",    # root/.env
        ]
        
        # Remove duplicates while preserving order
        unique_locations = []
        seen = set()
        for path in env_locations:
            path_resolved = path.resolve()
            if path_resolved not in seen:
                unique_locations.append(path)
                seen.add(path_resolved)
        
        for env_path in unique_locations:
            if env_path.exists():
                load_dotenv(env_path)
                break

    def _load_config(self) -> None:
        """Load all configuration from environment variables."""
        # AI Configuration
        self.aiConfig = AIConfig(
            api_key=os.getenv("AI_API_KEY", ""),
            provider=os.getenv("AI_PROVIDER", "litellm"),
            base_url=os.getenv("AI_BASE_URL", "https://grid.ai.juspay.net"),
            model_id=os.getenv("AI_MODEL_ID", "openai/qwen3-coder-480b"),
            vision_model_id=os.getenv("AI_VISION_MODEL_ID", "openai/glm-46-fp8"),
            project_id=os.getenv("AI_PROJECT_ID"),
            location=os.getenv("AI_LOCATION", "us-east5"),
            max_tokens=int(os.getenv("AI_MAX_TOKENS", "32768")),
            temperature=float(os.getenv("AI_TEMPERATURE", "0.7")),
            browser_headless=os.getenv("BROWSER_HEADLESS", "true").lower() == "true",
        )
        self.techSpecConfig = TechSpecConfig(
            output_dir=os.getenv("TECHSPEC_OUTPUT_DIR", "./output"),
            template_dir=os.getenv("TECHSPEC_TEMPLATE_DIR", "./templates"),
            temperature=float(os.getenv("TECHSPEC_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("TECHSPEC_MAX_TOKENS", "32768")),
            firecrawl_api_key=os.getenv("FIRECRAWL_API_KEY"),
            use_playwright=os.getenv("USE_PLAYWRIGHT", "true").lower() == "true",
        )
        self.logConfig = LogConfig(
            debug=os.getenv("DEBUG", "false").lower() == "true",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "grace.log"),
        )

        self.researchConfig = ResearchConfig(
            searchTool=os.getenv("SEARCH_TOOL", "searxng"),
            baseURL=os.getenv("SEARCH_BASE_URL", "https://localhost:32678"),
            formatType=os.getenv("SEARCH_FORMAT_TYPE", "markdown"),
            depth=int(os.getenv("SEARCH_DEPTH", "5")),
            proxy_url=os.getenv("SEARCH_PROXY_URL"),
            proxy_username=os.getenv("SEARCH_PROXY_USERNAME"),
            proxy_password=os.getenv("SEARCH_PROXY_PASSWORD"),
            with_ai_browser=os.getenv("WITH_AI_BROWSER", "true").lower() == "true",
        )

    def getAiConfig(self) -> AIConfig:
        return self.aiConfig
    
    def getTechSpecConfig(self) -> TechSpecConfig:
        return self.techSpecConfig
    
    def getLogConfig(self) -> LogConfig:
        return self.logConfig

    def getResearchConfig(self) -> ResearchConfig:
        return self.researchConfig


_config_instance: Optional[Config] = None


def get_config(env_file: Optional[str] = None) -> Config:
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(env_file)
    return _config_instance


def reload_config(env_file: Optional[str] = None):
    global _config_instance
    _config_instance = Config(env_file)
    return _config_instance
