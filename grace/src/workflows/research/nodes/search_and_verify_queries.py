from rich.console import Console
from rich.progress import Progress
from src.types.search.search_types import SearchResult
from src.ai.ai_service import AIService
from src.tools.search.SearchService import SearchService
from src.tools.browser.BrowserService import BrowserService
from src.tools.vision.vision import VisionAnalyzer
from src.utils.research.research_utils import generateConnectorName, verify_urls_relevance, extract_search_results_from_html
from typing import List
import asyncio

console = Console()
search = SearchService()
browser_service = BrowserService()
vision_analyzer = VisionAnalyzer()

async def browser_search_queries(queries: List[str], connector_name: str, llm_client: AIService) -> List[SearchResult]:
    search_results = []
    try:
      console.print(f"[green]Starting browser for search {'in headless' if browser_service.headless else 'in tab'}...[/green]")
      await browser_service.start()
      if not await browser_service.navigate_to("https://www.google.com"):
        console.print("Failed to navigate to Google")
      await browser_service.wait_for_load(1000)
            
      screenshot_b64 = await browser_service.take_screenshot()
      page_info = await browser_service.get_page_info()
            
      task = f"Find the Google search box and click on it to prepare for typing the search query"
      action_result = await vision_analyzer.analyze_screenshot(screenshot_b64, task, page_info)
      with Progress() as progress:
        progress.add_task(f"[bold]Searching[/bold]:", total=len(queries))
        for query in queries:
            progress.update(0, advance=1, description=f"query: {query}")
            await browser_service.navigate_to("https://www.google.com/search?q=" + query)
            await browser_service.wait_for_load()
            if action_result.get("action") == "click" and "coordinates" in action_result:
                x, y = action_result["coordinates"]
                await browser_service.click_coordinates(x, y)
                await browser_service.wait_for_load(1000)
                await browser_service.type_text(query)
                await browser_service.wait_for_load(1000)
                await browser_service.page.keyboard.press("Enter")
                locator = browser_service.page.locator("xpath=//span[text()='All']")
                await locator.first.wait_for(state="visible")
                html_content = await browser_service.get_markdown_content()
                structured_results = await extract_search_results_from_html(html_content, llm_client, query, connector_name)
                for result_item in structured_results:
                    search_result = SearchResult(
                        title=result_item.get("title", ""),
                        url=result_item.get("url", ""),
                        snippet=result_item.get("snippet", ""),
                        engine="google",
                        score=1.0
                    )
                    search_results.append(search_result)
        progress.stop()
    except Exception as e:
        console.print(f"Error in browser search: {str(e)}")
    finally:
        await browser_service.close()
    
    return search_results

def search_queries(urls, connector_name: str):
    try:
        if not asyncio.run(search.check_connection()):
            return []
        results = asyncio.run(search.search_multiple_queries(urls, score_words=connector_name))
        if(not results):
            console.print(f"Search returned {len(results)} results.")
        return results
    except Exception as e:
        console.print("error in searching", str(e))
        return []

def browser_search_queries_wrapper(urls: List[str], connector_name: str, llm_client: AIService) -> List[SearchResult]:
    try:
        results = asyncio.run(browser_search_queries(urls, connector_name, llm_client))
        if not results:
            console.print(f"Browser search returned {len(results)} results.")
        return results
    except Exception as e:
        console.print("error in browser searching", str(e))
        return []

def verify_results(results: List[SearchResult], llm_client: AIService, connector_name: str, query: str):
    try:
        urls = [{
            "title" : result.title,
            "url" : result.url,
            "snippet" : result.snippet,
            "relevance_score": result.score
        } for result in results]
        valid_links = verify_urls_relevance(urls,llm_client,connector_name, query)
        return valid_links
    except Exception as e:
        console.print("error in verifying", str(e))
        return [result.url for result in results]


def search_and_verify_queries(state):
    try:
        search_type = "traditional"
        llm_client = AIService(state["config"].getAiConfig())
        query = state["query"]
        queries = state.get("queries", [])[-1]
        connector_name = generateConnectorName(llm_client, query)
        state["connector_name"] = connector_name
        console.print(f"[green]Connector: {connector_name}[/green]")
        results = search_queries(queries, connector_name)
        if not results:
            console.print("[red]Search is not working[/red], [yellow]Now using browser search to find pages please wait[/yellow]")
            results = browser_search_queries_wrapper(queries, connector_name, llm_client)
        search_results = verify_results(results, llm_client, connector_name, query)
        if not search_results and search_type == "traditional":
            console.print("[red]No relevant search results found after verification.[/red]")
            # search_type = "ai"
            results = browser_search_queries_wrapper(queries, connector_name, llm_client)
            search_results = verify_results(results, llm_client, connector_name, query)
        if not search_results:
            state['error'] = "No relevant search results found."
        state["search_results"] = search_results

    except Exception as e:
        console.print(f"Error in search_and_verify_queries: {str(e)}")
        state["search_results"] = []
        return state
    
    return state
