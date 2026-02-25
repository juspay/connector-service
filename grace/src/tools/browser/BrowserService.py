import base64
from typing import Optional, Dict, Any, List
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
import logging
from markdownify import MarkdownConverter
from src.config import get_config
from src.utils.html.html_extractor import extract_body_and_clickable_elements, extract_search_results_optimized

logger = logging.getLogger(__name__)

class BrowserService:
    def __init__(self, headless: bool = True, viewport_width: int = 1280, viewport_height: int = 720):
        self.headless = get_config().getAiConfig().browser_headless if get_config() else headless
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.playwright = None
        self.markdownConverter = MarkdownConverter()
        
    async def start(self):
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=self.headless,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--disable-extensions',
                    '--disable-plugins',
                    '--disable-default-apps',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding',
                    '--disable-background-networking',
                    '--disable-sync',
                    '--metrics-recording-only',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-default-apps',
                    '--disable-translate',
                    '--disable-prompt-on-repost',
                    '--disable-hang-monitor',
                    '--disable-ipc-flooding-protection',
                    '--disable-client-side-phishing-detection',
                    '--disable-component-extensions-with-background-pages',
                    '--disable-logging',
                    '--disable-features=TranslateUI',
                    '--disable-features=TranslateUI,BlinkGenPropertyTrees',
                    '--disable-features=IsolateOrigins,site-per-process'
                ]
            )
            
            self.context = await self.browser.new_context(
                viewport={'width': self.viewport_width, 'height': self.viewport_height},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                locale='en-US',
                timezone_id='America/New_York',
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'Cache-Control': 'max-age=0',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                }
            )
            
            self.page = await self.context.new_page()
            
            # Hide webdriver property to avoid detection
            await self.page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                
                // Override permissions API
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
                
                // Remove automation indicators
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
                delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
            """)
            
            logger.info("Browser started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start browser: {e}")
            raise
    
    async def close(self):
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("Browser closed successfully")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")
    
    async def navigate_to(self, url: str) -> bool:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            # self.browser.close()
            # await self.start()
            self.page = await self.context.new_page()
            # Use domcontentloaded instead of networkidle for better reliability
            response = await self.page.goto(url, wait_until='load')            
            success = response.status < 400 if response else False
            
            if success:
                logger.info(f"Successfully navigated to {url}")
                # Additional wait for dynamic content to load
                await self.page.wait_for_timeout(3000)
            else:
                logger.warning(f"Navigation to {url} returned status {response.status if response else 'None'}")
            return success
        except Exception as e:
            logger.error(f"Failed to navigate to {url}: {e}")
            return False
    
    async def take_screenshot(self, quality: int = 80) -> str:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            screenshot_bytes = await self.page.screenshot(type='jpeg', quality=quality)
            
            # Convert to base64
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')

            logger.info("Screenshot captured successfully")
            return screenshot_b64
        
        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            raise
    
    async def click_coordinates(self, x: int, y: int) -> bool:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            # Move mouse to coordinates first for better accuracy
            await self.page.mouse.move(x, y)
            await self.page.wait_for_timeout(100)  # Small delay for mouse move
            
            # Click at the coordinates
            await self.page.mouse.click(x, y)
            await self.page.wait_for_timeout(1500)  # Wait for any animations/loading
            
            logger.info(f"Clicked at coordinates ({x}, {y})")
            return True
        
        except Exception as e:
            logger.error(f"Failed to click at ({x}, {y}): {e}")
            return False
    
    async def click_element_if_exists(self, selector: str) -> bool:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            element = await self.page.query_selector(selector)
            if element:
                await element.click()
                await self.page.wait_for_timeout(1000)
                logger.info(f"Successfully clicked element with selector: {selector}")
                return True
            else:
                logger.warning(f"Element not found with selector: {selector}")
                return False
        
        except Exception as e:
            logger.error(f"Failed to click element {selector}: {e}")
            return False
    
    async def type_text(self, text: str) -> bool:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            await self.page.keyboard.type(text)
            logger.info(f"Typed text: {text}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to type text: {e}")
            return False
    
    async def scroll(self, direction: str = "down", pixels: int = 300) -> bool:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            if direction.lower() == "down":
                await self.page.mouse.wheel(0, pixels)
            elif direction.lower() == "up":
                await self.page.mouse.wheel(0, -pixels)
            else:
                logger.warning(f"Unknown scroll direction: {direction}")
                return False
            
            await self.page.wait_for_timeout(500)  # Wait for scroll to complete
            logger.info(f"Scrolled {direction} by {pixels} pixels")
            return True
        
        except Exception as e:
            logger.error(f"Failed to scroll: {e}")
            return False
    
    async def get_page_info(self) -> Dict[str, Any]:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            viewport_size = None
            try:
                viewport_size = self.page.viewport_size
            except Exception as viewport_error:
                viewport_size = {'width': self.viewport_width, 'height': self.viewport_height}
            info = {
                'url': self.page.url,
                'title': await self.page.title(),
                'viewport': viewport_size
            }
            
            return info
        
        except Exception as e:
            logger.error(f"Failed to get page info: {e}")
            return {}
    
    async def get_clickable_elements_info(self) -> List[Dict[str, Any]]:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            # Get all potentially clickable elements
            elements_info = await self.page.evaluate("""
                () => {
                    const clickableSelectors = [
                        'button',
                        'input[type="button"]',
                        'input[type="submit"]',
                        'input[type="text"]',
                        'input[type="email"]',
                        'input[type="password"]',
                        'input[type="search"]',
                        'textarea',
                        'select',
                        'a[href]',
                        '[onclick]',
                        '[role="button"]',
                        '[tabindex]'
                    ];
                    
                    const elements = [];
                    
                    clickableSelectors.forEach(selector => {
                        document.querySelectorAll(selector).forEach(el => {
                            const rect = el.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) {
                                elements.push({
                                    tag: el.tagName.toLowerCase(),
                                    type: el.type || 'none',
                                    text: el.textContent?.trim().substring(0, 50) || '',
                                    placeholder: el.placeholder || '',
                                    x: Math.round(rect.left + rect.width / 2),
                                    y: Math.round(rect.top + rect.height / 2),
                                    width: Math.round(rect.width),
                                    height: Math.round(rect.height),
                                    visible: rect.top >= 0 && rect.left >= 0 && 
                                            rect.bottom <= window.innerHeight && 
                                            rect.right <= window.innerWidth
                                });
                            }
                        });
                    });
                    
                    return elements;
                }
            """)
            
            logger.info(f"Found {len(elements_info)} clickable elements")
            return elements_info
        
        except Exception as e:
            logger.error(f"Failed to get clickable elements: {e}")
            return []
    
    async def highlight_coordinates(self, x: int, y: int, duration: int = 2000):
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            await self.page.evaluate(f"""
                (coords) => {{
                    const highlight = document.createElement('div');
                    highlight.style.position = 'fixed';
                    highlight.style.left = '{x - 10}px';
                    highlight.style.top = '{y - 10}px';
                    highlight.style.width = '20px';
                    highlight.style.height = '20px';
                    highlight.style.backgroundColor = 'red';
                    highlight.style.border = '2px solid yellow';
                    highlight.style.borderRadius = '50%';
                    highlight.style.zIndex = '10000';
                    highlight.style.pointerEvents = 'none';
                    document.body.appendChild(highlight);
                    
                    setTimeout(() => {{
                        if (highlight.parentNode) {{
                            highlight.parentNode.removeChild(highlight);
                        }}
                    }}, {duration});
                }}
            """)
            
            logger.info(f"Added visual highlight at ({x}, {y})")
        
        except Exception as e:
            logger.error(f"Failed to add highlight: {e}")
    

    async def wait_for_load(self, timeout: int = 1000):
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            await self.page.wait_for_load_state()
            logger.info("Page loaded successfully")
        
        except Exception as e:
            logger.error(f"Failed to wait for page load: {e}")
    
    async def get_optimized_html_content(self) -> str:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            # Retry mechanism for content extraction
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    html_content = await self.page.content()
                    optimized_content = extract_body_and_clickable_elements(html_content)
                    return optimized_content
                except Exception as content_error:
                    if "navigating" in str(content_error).lower() and attempt < max_retries - 1:
                        logger.info(f"Page still navigating, retrying in 1 second... (attempt {attempt + 1}/{max_retries})")
                        await self.page.wait_for_timeout(1000)
                        continue
                    else:
                        raise content_error
        
        except Exception as e:
            logger.error(f"Failed to get optimized HTML content: {e}")
            return ""
    
    async def get_optimized_search_results(self, query: str) -> str:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            
            # Wait for page to be stable before getting content
            await self.page.wait_for_load_state('domcontentloaded', timeout=10000)
            await self.page.wait_for_timeout(500)  # Brief wait for dynamic content
            
            # Retry mechanism for content extraction
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    html_content = await self.page.content()
                    optimized_content = extract_search_results_optimized(html_content, query)

                    logger.info(f"Extracted optimized search results (reduced from {len(html_content)} to {len(optimized_content)} characters)")
                    return optimized_content
                except Exception as content_error:
                    if "navigating" in str(content_error).lower() and attempt < max_retries - 1:
                        logger.info(f"Page still navigating, retrying in 1 second... (attempt {attempt + 1}/{max_retries})")
                        await self.page.wait_for_timeout(1000)
                        continue
                    else:
                        raise content_error
        
        except Exception as e:
            logger.error(f"Failed to get optimized search results: {e}")
            return ""

        
    async def get_markdown_content(self) -> str:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
                    
            # Retry mechanism for content extraction
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    html_content = await self.page.content()
                    markdown_content = self.markdownConverter.convert(html_content)
                    return markdown_content
                except Exception as content_error:
                    if "navigating" in str(content_error).lower() and attempt < max_retries - 1:
                        logger.info(f"Page still navigating, retrying in 1 second... (attempt {attempt + 1}/{max_retries})")
                        await self.page.wait_for_timeout(1000)
                        continue
                    else:
                        raise content_error
        
        except Exception as e:
            logger.error(f"Failed to get markdown content: {e}")
            return ""

    async def get_page_content(self) -> str:
        try:
            if not self.page:
                raise RuntimeError("Browser not started. Call start() first.")
            await self.page.wait_for_timeout(1000)

            max_retries = 3
            for attempt in range(max_retries):
                try:
                    html_content = await self.page.content()
                    return html_content
                except Exception as content_error:
                    if "navigating" in str(content_error).lower() and attempt < max_retries - 1:
                        logger.info(f"Page still navigating, retrying in 1 second... (attempt {attempt + 1}/{max_retries})")
                        await self.page.wait_for_timeout(1000)
                        continue
                    else:
                        raise content_error
        
        except Exception as e:
            logger.info(f"Failed to get page content: {e}")
            return ""