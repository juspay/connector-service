import json
from src.ai.ai_service import AIService
from src.ai.system.prompt_config import prompt_config
from typing import  List, Tuple, Dict, Any

def generate_search_queries(connector_name: str, llm_client: AIService) -> Tuple[str, bool, str]:
    prompt = prompt_config().get_with_values("searchQueryPrompt", {"connector_name": connector_name}) or ""
    messages = [{"role": "user", "content": prompt}]
    return llm_client.generate(messages=messages)

def generateConnectorName(llm_client: AIService, query: str) -> str:
    prompt = prompt_config().get_with_values("connectorNamePrompt", {"query": query}) or ""
    messages = [{"role": "user", "content": prompt}]
    response, _, _ = llm_client.generate(messages=messages, max_tokens=10)
    return response.strip()

def verify_urls_relevance(urls, llm_client: AIService, connector_name: str, query: str) -> List[str]:
    prompt = prompt_config().get_with_values("urlsRelevancePrompt", {
        "urls": str(urls),
        "connector_name": connector_name,
        "query": query
    })
    messages = [{"role": "user", "content": prompt}]
    response, _, error = llm_client.generate(messages=messages)
    if error:
        return [url["url"] for url in urls]
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        return [url["url"] for url in urls]

async def extract_search_results_from_html(html_content: str, llm_client: AIService, query: str, connector_name: str) -> List[Dict[str, Any]]:
    try:
        prompt = prompt_config().get_with_values("searchResultExtractionFromHTML", {
            "html_content": html_content,
            "query": query,
            "connector_name": connector_name
        })
        messages = [{"role": "user", "content": prompt}]
        response, success, error = llm_client.generate(messages)
        if success and response:
            try:
                # Parse the JSON response
                results = json.loads(response.strip())
                if isinstance(results, list):
                    return results
                else:
                    return []
            except json.JSONDecodeError as e:
                return []
        else:
            return []
    except Exception as e:
        print(f"Error in extracting search results from HTML: {str(e)}")
        return []

def validate_page_content(llm_client: AIService, connector_name: str, query: str, page_content: str, url: str) -> Dict[str, Any]:
    prompt = prompt_config().get_with_values("pageContentValidationPrompt", {
        "connector_name": connector_name,
        "query": query
    })
    messages = [{
        "role": "system",
        "content": prompt
    }, {
        "role": "user",
        "content": "Here is the page content:\n" + page_content + f"\nURL: {url}"
    }]
    response, success, error = llm_client.generate(messages=messages)
    if success and response:
        try:
            print("Validation Response:", response)
            validation_result = json.loads(response.strip())
            return validation_result
        except json.JSONDecodeError:
            return {"is_relevant": False, "reason": "Invalid JSON response"}
    else:
        return {"is_relevant": False, "reason": error or "LLM generation failed"}