import asyncio

from src.ai.ai_service import AIService
from ..states.research_state import WorkflowState
from src.tools.browser import ScrapingService
from rich.console import Console
from src.utils.filemanager_tools import save_file
from src.utils.research.research_utils import validate_page_content
console = Console()


def validate_page(llm_client, connector_name: str, query: str, result: dict):
    result = validate_page_content(llm_client, connector_name, query, result["html_content"], result["url"])
    return result

def scrap_links_and_analyse_pages(state: WorkflowState) -> WorkflowState:
      async def scrape_with_cleanup():
          async with ScrapingService() as scraping_service:
              llm_client = AIService(state["config"].getAiConfig())
              urls = state["search_results"]
              query = state["query"]
              connector_name = state["connector_name"]
              fileManager = state["file_manager"]
              fileManager.update_base_path(".grace/research/scraped_pages/" + connector_name)
              
              def callback(result):
                  try:
                      if result and result["status"] == "success":
                          analysis = validate_page(llm_client, connector_name, query, result)
                          if analysis.get("is_relevant", True):
                              state["visited_urls"].append(result["url"])
                              save_file(result, fileManager)
                      elif result and result["status"] == "error":
                          state["scrapping_failed_pages"].append(result["url"])
                  except Exception as e:
                      console.print(f"Error occurred while processing {result['url']}: {e}")
              
              return await scraping_service.scrape_multiple_pages(urls=urls, callback=callback)
      
      try:
          # Run the async scraping with proper cleanup
          asyncio.run(scrape_with_cleanup())
      except Exception as e:
          console.print(f"Error occurred while scraping: {e}")
      
      return state
