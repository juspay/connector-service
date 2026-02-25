from src.config import get_config
from .BrowserService import BrowserService
from rich.console import Console
import asyncio
import aiohttp
import tempfile
import os
import json
import yaml
from typing import List, Optional, Callable, Any
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from pathlib import Path

class ScrapingService:        
    def __init__(self, config=None, headless: bool = True):
        self.browser_service = None
        self._headless = headless
        self.console = Console()
        self.config = config or get_config().getResearchConfig()
        self._pages_data = []
        self._browser_pool = []
        self._pool_size = 5
    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - ensures proper cleanup."""
        await self.close()

    @asynccontextmanager
    async def _get_browser_service(self):
        service = None
        try:
            if self._browser_pool:
                service = self._browser_pool.pop()
            else:
                service = BrowserService(headless=self._headless)
                await service.start()
            yield service
        except Exception as e:
            self.console.log(f"Browser service error: {e}")
            if service:
                await service.close()
            raise
        finally:
            if service and len(self._browser_pool) < self._pool_size:
                self._browser_pool.append(service)
            elif service:
                await service.close()

    @asynccontextmanager
    async def _get_session(self):
        timeout = aiohttp.ClientTimeout(total=120, connect=30, sock_read=60)
        connector = aiohttp.TCPConnector(
            limit=100, 
            limit_per_host=10,
            enable_cleanup_closed=True,
            keepalive_timeout=30
        )
        session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': 'ScrapingService/1.0'}
        )
        try:
            yield session
        finally:
            await session.close()
            await asyncio.sleep(0.1)  # Allow connections to close


    def _is_pdf_url(self, url: str) -> bool:
        url_lower = url.lower()
        parsed_url = urlparse(url_lower)
        path = parsed_url.path
        return (path.endswith('.pdf') or 
                'pdf' in parsed_url.query or
                'application/pdf' in url_lower)

    def _is_document_url(self, url: str) -> str:
        url_lower = url.lower()
        parsed_url = urlparse(url_lower)
        path = parsed_url.path
        
        if path.endswith('.pdf') or 'application/pdf' in url_lower:
            return 'pdf'
        elif path.endswith(('.yaml', '.yml')) or 'yaml' in parsed_url.query:
            return 'yaml'
        elif path.endswith('.json') or 'application/json' in url_lower:
            return 'json'
        return ''

    async def _check_content_type(self, url: str) -> str:
        try:
            async with self._get_session() as session:
                async with session.head(url, timeout=10) as response:
                    content_type = response.headers.get('content-type', '').lower()
                    return content_type
        except Exception as e:
            self.console.log(f"Could not determine content type for {url}: {e}")
            return ""

    def _detect_document_type_from_content_type(self, content_type: str) -> str:
        content_type = content_type.lower()
        if 'pdf' in content_type:
            return 'pdf'
        elif 'yaml' in content_type or 'yml' in content_type:
            return 'yaml'
        elif 'json' in content_type:
            return 'json'
        return ''

    async def _download_pdf(self, url: str) -> Optional[str]:
        try:
            async with self._get_session() as session:
                self.console.print(f"Downloading PDF: {url}")
                
                async with session.get(url, timeout=60) as response:
                    if response.status != 200:
                        return None
                    
                    content_type = response.headers.get('content-type', '').lower()
                    if 'pdf' not in content_type:
                        self.console.log(f"Warning: Content type {content_type} may not be PDF")
                    
                    # Create temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
                        temp_path = tmp_file.name
                        
                        # Write PDF content to temporary file
                        async for chunk in response.content.iter_chunked(8192):
                            tmp_file.write(chunk)
                    
                    # Extract text from PDF
                    text_content = await self._extract_pdf_text(temp_path)
                    
                    # Clean up temporary file
                    os.unlink(temp_path)
                    
                    return text_content
                
        except Exception as e:
            self.console.log(f"Error downloading/processing PDF {url}: {e}")
            return None

    async def _extract_pdf_text(self, pdf_path: str) -> str:
        text_content = ""
        
        # Try PyPDF2 first
        try:
            import PyPDF2
            text_content = await self._extract_with_pypdf2(pdf_path)
            if text_content and len(text_content.strip()) > 50:
                return text_content
        except ImportError:
            self.console.log("PyPDF2 not available, trying pdfplumber")
        except Exception as e:
            self.console.log(f"PyPDF2 extraction failed: {e}")
        
        return text_content or "Could not extract text from PDF"

    async def _extract_with_pypdf2(self, pdf_path: str) -> str:
        import PyPDF2
        
        text_parts = []
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            for page_num, page in enumerate(pdf_reader.pages):
                try:
                    text = page.extract_text()
                    if text.strip():
                        text_parts.append(f"\n--- Page {page_num + 1} ---\n{text}")
                except Exception as e:
                    self.console.log(f"Error extracting page {page_num + 1}: {e}")
        
        return "\n".join(text_parts)

    async def _download_document(self, url: str, doc_type: str) -> Optional[str]:
        try:
            async with self._get_session() as session:
                self.console.print(f"Downloading {doc_type.upper()}: {url}")
                
                async with session.get(url, timeout=60) as response:
                    if response.status != 200:
                        return None
                    
                    content = await response.text()
                    
                    if doc_type == 'yaml':
                        return self._format_yaml_content(content)
                    elif doc_type == 'json':
                        return self._format_json_content(content)
                    
                    return content
                
        except Exception as e:
            self.console.log(f"Error downloading {doc_type} {url}: {e}")
            return None

    def _format_yaml_content(self, content: str) -> str:
        try:
            # Parse and re-format YAML for consistency
            parsed = yaml.safe_load(content)
            formatted = yaml.dump(parsed, default_flow_style=False, indent=2)
            return f"```yaml\n{formatted}\n```"
        except Exception:
            # Return original content if parsing fails
            return f"```yaml\n{content}\n```"

    def _format_json_content(self, content: str) -> str:
        try:
            # Parse and pretty-print JSON
            parsed = json.loads(content)
            formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
            return f"```json\n{formatted}\n```"
        except Exception:
            # Return original content if parsing fails
            return f"```json\n{content}\n```"

    async def scrape(self, url: str, browser_service: BrowserService = None) -> Optional[dict]:
        if not url or not url.strip():
            return {'url': url, 'error': 'Empty URL provided', 'status': 'error'}
        
        # Check document type from URL
        doc_type = self._is_document_url(url)
        
        if not doc_type:
            # Check content type if URL doesn't indicate document type
            content_type = await self._check_content_type(url)
            doc_type = self._detect_document_type_from_content_type(content_type)
        
        # Handle document downloads
        if doc_type:
            return await self._scrape_document(url, doc_type)
        
        # Regular web page scraping
        if browser_service:
            return await self._scrape_with_service(url, browser_service)
        
        async with self._get_browser_service() as service:
            return await self._scrape_with_service(url, service)

    async def _scrape_document(self, url: str, doc_type: str) -> dict:
        try:
            self.console.print(f"Processing {doc_type.upper()}: {url}")
            
            if doc_type == 'pdf':
                content = await self._download_pdf(url)
            else:
                content = await self._download_document(url, doc_type)
            
            if content is None:
                return {
                    'url': url,
                    'error': f'Failed to download or process {doc_type.upper()}',
                    'status': 'error'
                }
            
            title = self._extract_document_title(url, doc_type)
            
            return {
                'url': url,
                'title': title,
                'html_content': content,
                'content_type': doc_type,
                'status': 'success'
            }
            
        except Exception as e:
            self.console.log(f"Error processing {doc_type} {url}: {e}")
            return {
                'url': url,
                'error': str(e),
                'status': 'error'
            }

    def _extract_document_title(self, url: str, doc_type: str) -> str:
        parsed_url = urlparse(url)
        filename = Path(parsed_url.path).name
        
        if filename:
            # Remove extension and format name
            title = filename.rsplit('.', 1)[0] if '.' in filename else filename
            title = title.replace('_', ' ').replace('-', ' ').title()
            return title
        
        return f"{doc_type.upper()} Document"

    async def _scrape_pdf(self, url: str) -> dict:
        try:
            self.console.print(f"Processing PDF: {url}")
            
            pdf_content = await self._download_pdf(url)
            
            if pdf_content is None:
                return {
                    'url': url,
                    'error': 'Failed to download or process PDF',
                    'status': 'error'
                }
            
            title = self._extract_pdf_title(url, pdf_content)
            
            return {
                'url': url,
                'title': title,
                'html_content': pdf_content,
                'content_type': 'pdf',
                'status': 'success'
            }
            
        except Exception as e:
            self.console.log(f"Error processing PDF {url}: {e}")
            return {
                'url': url,
                'error': str(e),
                'status': 'error'
            }

    def _extract_pdf_title(self, url: str, content: str) -> str:
        parsed_url = urlparse(url)
        filename = Path(parsed_url.path).name
        if filename and filename.lower().endswith('.pdf'):
            title = filename[:-4].replace('_', ' ').replace('-', ' ').title()
            return title
        if content:
            lines = content.strip().split('\n')
            for line in lines[:10]:
                line = line.strip()
                if len(line) > 10 and len(line) < 100:
                    return line
        
        return "PDF Document"

    async def _scrape_with_service(self, url: str, service: BrowserService) -> Optional[dict]:
        try:
            if service.browser is None:
                await service.start()
            
            navigation_success = await asyncio.wait_for(
                service.navigate_to(url), timeout=30.0
            )
            
            if not navigation_success:
                return {
                    'url': url,
                    'error': 'Failed to navigate to URL',
                    'status': 'error'
                }
            
            await service.wait_for_load(2000)
            
            page_info_task = asyncio.create_task(service.get_page_info())
            content_task = asyncio.create_task(service.get_markdown_content())
            
            page_info, html_content = await asyncio.gather(
                page_info_task, content_task, return_exceptions=True
            )
            
            if isinstance(page_info, Exception):
                page_info = {}
            if isinstance(html_content, Exception):
                html_content = ""
            
            return {
                'url': url,
                'title': page_info.get('title', '') if page_info else '',
                'html_content': html_content if html_content else '',
                'status': 'success'
            }

        except asyncio.TimeoutError:
            return {
                'url': url,
                'error': 'Request timed out',
                'status': 'error'
            }
        except Exception as e:
            self.console.log(f"Error scraping {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'status': 'error'
            }

    async def scrape_with_ai(self, url: str, browser_service: BrowserService = None) -> Optional[dict]:
        # TODO: Implement AI-based content analysis and extraction
        return await self.scrape(url, browser_service)

    async def _scrape_single_url(self, url: str) -> Optional[dict]:
        use_ai = getattr(self.config, 'with_ai_browser', False)
        
        if use_ai:
            return await self.scrape_with_ai(url)
        else:
            return await self.scrape(url)

    async def scrape_multiple_pages(
        self, 
        urls: List[str], 
        callback: Optional[Callable[[Any], None]] = None, 
        parallel_count: int = 3,
        clear_previous_data: bool = True
    ) -> List[dict]:
        if not urls:
            self.console.print("No URLs provided for scraping")
            return []
        
        if clear_previous_data:
            self._pages_data.clear()
        
        valid_urls = [url.strip() for url in urls if url and url.strip()]
        if len(valid_urls) != len(urls):
            self.console.print(f"Filtered {len(urls) - len(valid_urls)} invalid URLs")
        
        if not valid_urls:
            return []
        
        optimal_parallel = min(parallel_count, len(valid_urls), 10)
        
        try:
            if optimal_parallel <= 1:
                return await self._scrape_sequential(valid_urls, callback)
            else:
                return await self._scrape_parallel(valid_urls, callback, optimal_parallel)
        finally:
            # Clean up browser pool but keep session for reuse
            await self._cleanup_browser_pool()

    async def _scrape_sequential(self, urls: List[str], callback: Optional[Callable] = None) -> List[dict]:
        results = []
        
        for i, url in enumerate(urls):
            self.console.print(f"Scraping {i+1}/{len(urls)}: {url}")
            
            result = await self._scrape_single_url(url)
            results.append(result)
            self._pages_data.append(result)
            
            if callback and result:
                await self._execute_callback(callback, result, url)
        
        return results

    async def _scrape_parallel(self, urls: List[str], callback: Optional[Callable], parallel_count: int) -> List[dict]:
        semaphore = asyncio.Semaphore(parallel_count)
        
        async def scrape_with_semaphore(url: str, index: int) -> dict:
            async with semaphore:
                self.console.print(f"Scraping {index+1}/{len(urls)}: {url}")
                
                result = await self._scrape_single_url(url)
                
                if callback and result:
                    await self._execute_callback(callback, result, url)
                
                return result
        
        tasks = [scrape_with_semaphore(url, i) for i, url in enumerate(urls)]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results = []
        successful_count = 0
        error_count = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_result = {
                    'url': urls[i],
                    'error': str(result),
                    'status': 'error'
                }
                processed_results.append(error_result)
                self._pages_data.append(error_result)
                error_count += 1
            else:
                processed_results.append(result)
                self._pages_data.append(result)
                if result and result.get('status') == 'success':
                    successful_count += 1
                else:
                    error_count += 1
        
        self.console.print(f"Scraping completed: {successful_count} successful, {error_count} errors")
        return processed_results

    async def _execute_callback(self, callback: Callable, result: dict, url: str):
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(result)
            else:
                callback(result)
        except Exception as e:
            self.console.log(f"Error in callback for {url}: {e}")

    async def _cleanup_browser_pool(self):
        while self._browser_pool:
            browser_service = self._browser_pool.pop()
            try:
                await browser_service.close()
            except Exception as e:
                self.console.log(f"Error closing browser service: {e}")

    async def close(self):
        try:
            # Close browser pool
            await self._cleanup_browser_pool()
            
            # Close main browser service if exists
            if self.browser_service:
                await self.browser_service.close()
                self.browser_service = None
            
        except Exception as e:
            self.console.log(f"Error during cleanup: {e}")
