from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx
from src.types import SearchResult
from src.config import Config
from rich.progress import Progress
from rich.console import Console

console = Console()

class SearchService:

    def __init__(self, searxng_base_url: Optional[str] = None):
        self.config = Config()
        if self.config.researchConfig.searchTool != "searxng":
            raise ValueError("Only SearxNG search tool is supported currently")
        self.searxng_base_url = searxng_base_url or self.config.researchConfig.baseURL

    def _get_client_config(self, timeout: float = 10.0) -> dict:
        client_config = {"timeout": timeout}
        
        # Add proxy configuration if available
        if self.config.researchConfig.proxy_url:
            client_config["proxies"] = self.config.researchConfig.proxy_url
            
            # Add proxy authentication if provided
            if (self.config.researchConfig.proxy_username and 
                self.config.researchConfig.proxy_password):
                import httpx
                client_config["auth"] = httpx.BasicAuth(
                    self.config.researchConfig.proxy_username,
                    self.config.researchConfig.proxy_password
                )
        
        return client_config

    async def check_connection(self) -> bool:
        try:
            client_config = self._get_client_config(timeout=5.0)
            async with httpx.AsyncClient(**client_config) as client:
                response = await client.get(f"{self.searxng_base_url}/healthz")
                if response.status_code == 200:
                    return True
                # Fallback: try the main endpoint
                response = await client.get(f"{self.searxng_base_url}")
                return response.status_code == 200
        except Exception as error:
            console.print(f"SearxNG connection failed: {error}")
            return False

    async def search(
        self,
        query: str,
        engines: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        limit: int = 10,
        special_words: Optional[str] = None
    ):
        try:
            params = {
                'q': query,
                'format': 'json',
                'engines': ','.join(engines or ['google', 'bing', 'duckduckgo']),
                'categories': ','.join(categories or ['general']),
                'results_on_new_tab': '1',
            }

            client_config = self._get_client_config(timeout=10.0)
            async with httpx.AsyncClient(**client_config) as client:
                response = await client.get(
                    f"{self.searxng_base_url}/search",
                    params=params,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'application/json',
                    }
                )
                response.raise_for_status()

            # Check if response is JSON
            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type:
                raise Exception("SearxNG returned HTML instead of JSON - configuration issue")

            data = response.json()
            if not isinstance(data, dict):
                raise Exception("Invalid JSON response from SearxNG")

            results = data.get('results', [])
            if not isinstance(results, list):
                raise Exception("Invalid results format from SearxNG")

            search_results = [
                SearchResult(
                    title=result.get('title', 'Untitled'),
                    url=result['url'],
                    snippet=result.get('content') or result.get('snippet', ''),
                    engine=result.get('engine', 'unknown'),
                    score=self._calculate_score(result, index, special_words)
                )
                for index, result in enumerate(results)
                if result.get('url') and result.get('title') and self._calculate_score(result, index, special_words) > 0.1
            ]
            return search_results

        except Exception as error:
            console.print(f"Search error for query '{query}': {error}")
            return []

    def _calculate_score(self, result: Dict[str, Any], index: int, special_words: Optional[str] = None) -> float:
        score = 1.0 - index * 0.05
        if result.get('title') and len(result['title']) > 10:
            score += 0.1
        if result.get('content') and len(result['content']) > 100:
            score += 0.1
        if 'https://' in result.get('url', ''):
            score += 0.05
        
        url = result.get('url', '')
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
        
            if any(keyword in domain for keyword in ['docs', 'api']):
                score += 0.1 

            if special_words and any(word in domain for word in special_words.split(" ")):
                score += 0.2
            else:
                if any(keyword not in domain.split(".") for keyword in special_words.split(" ")):
                    score = 0.0
                else:
                    score = 0.1
                
        except Exception:
            # Fallback to original behavior if URL parsing fails
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in ['reference', 'docs', 'api']):
                score += 0.2
        
        return max(0.1, min(1.0, score))
    
    async def search_multiple_queries(
        self,
        queries: List[str],
        max_results_per_query: int = 10,
        engines: Optional[List[str]] = None,
        score_words: Optional[str] = None
    ) -> List[SearchResult]:
        all_results: List[SearchResult] = []
        seen_urls = set()
        with Progress() as progress:
            progress_task = progress.add_task("[cyan]Searching queries...", total=len(queries))
            for query in queries:
                try:
                    results = await self.search(
                        query,
                        engines=engines,
                        limit=max_results_per_query,
                        special_words=score_words
                    )
                    # Deduplicate by URL
                    for result in results:
                        if result.url not in seen_urls:
                            seen_urls.add(result.url)
                            all_results.append(result)
                except Exception as error:
                    continue
                finally:
                    progress.update(progress_task, advance=1)

        return sorted(all_results, key=lambda r: r.score, reverse=True)

    async def is_engine_available(self, engine: str) -> bool:
        try:
            client_config = self._get_client_config(timeout=5.0)
            async with httpx.AsyncClient(**client_config) as client:
                response = await client.get(f"{self.searxng_base_url}/config")
                data = response.json()
                engines = data.get('engines', {})
                return engine in engines
        except Exception:
            return False

    async def get_available_engines(self) -> List[str]:
        try:
            client_config = self._get_client_config(timeout=5.0)
            async with httpx.AsyncClient(**client_config) as client:
                response = await client.get(f"{self.searxng_base_url}/config")
                data = response.json()
                engines = data.get('engines', {})
                return [
                    name for name, config in engines.items()
                    if config.get('enabled', False)
                ]
        except Exception:
            return []
