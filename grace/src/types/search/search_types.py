from dataclasses import dataclass

@dataclass
class SearchResult:
    """Search result from search engine."""
    title: str
    url: str
    snippet: str
    engine: str
    score: float