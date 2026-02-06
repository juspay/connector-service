from typing import Optional
from dataclasses import dataclass
from rich.console import Console
console = Console()

@dataclass
class AIConfig:
    """AI provider configuration."""
    api_key: str
    provider: str = "litellm"
    base_url: str = "https://grid.juspay.net"
    model_id: str = "openai/qwen3-coder-480b"
    vision_model_id: str = "openai/glm-46-fp8"
    project_id: Optional[str] = None
    max_tokens: int = 50000
    location: str = "us-east5"
    temperature: float = 0.7
    browser_headless: bool = True

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if self.provider == "litellm" and not self.api_key:
            raise ValueError("API key must be specified")
        
@dataclass
class TechSpecConfig:
    """Technical specifications configuration."""
    output_dir: str = "./output"
    template_dir: str = "./templates"
    temperature : float = 0.7
    max_tokens : int = 50000
    firecrawl_api_key: Optional[str] = None
    use_playwright: bool = False

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.output_dir:
            raise ValueError("Output directory must be specified")
        if not self.template_dir:
            raise ValueError("Template directory must be specified")
        if not self.firecrawl_api_key:
            console.print("[red]Firecrawl is not found, using playwright[/red]")
            self.use_playwright = True  # Default to True if no API key

@dataclass
class ResearchConfig:
    
    # Search configuration
    searchTool: str = "searxng"
    baseURL: str = "https://localhost:32678"

    formatType: str = "markdown"
    depth: int = 5

    with_ai_browser: bool = False
    
    
    # Proxy configuration
    proxy_url: Optional[str] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if self.searchTool not in ["searxng"]:
            raise ValueError(f"Invalid search engine: {self.searchTool}")

@dataclass
class LogConfig:
    """Logging configuration."""
    log_level: str = "INFO"
    log_file: str = "grace.log"
    debug: bool = False

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_levels:
            raise ValueError(f"Invalid log level: {self.log_level}")
