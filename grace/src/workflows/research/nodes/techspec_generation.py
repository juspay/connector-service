import json
from pathlib import Path
from typing import Dict, List

from rich.console import Console

from src.ai.ai_service import AIService
from src.ai.system.prompt_config import prompt_config
from src.tools.filemanager.filemanager import FileManager
from src.utils.transformations import sanitize_filename

from ..states.research_state import WorkflowState
from src.ai.ai_service import AIService
from rich.console import Console
console = Console()


def load_visited_pages(
    file_manager: FileManager, visited_urls: list[str]
) -> list[dict[str, str]]:
    pages = []
    for url in visited_urls:
        filename = sanitize_filename(url)
        content = file_manager.read_file(filename)
        pages.append({"url": url, "content": content})
    return pages


def generate_techspec_content(llm_client: AIService, pages) -> str:
    try:
        # Placeholder implementation for techspec content generation
        prompt = prompt_config().get_with_values(
            "techspecPrompt",
            {
                "content": "provide a detailed technical specification based on the following documentation pages."
            },
        )
        messages = [
            {"role": "system", "content": prompt},
            *[{"role": "user", "content": page["content"]} for page in pages],
        ]
        techspec_content, success, error = llm_client.generate(messages=messages)
        if success:
            return techspec_content
        return ""
    except Exception as e:
        return "", False, str(e)


def techspec_generation(state: WorkflowState) -> WorkflowState:
    try:
        if not state["visited_urls"]:
            console.print("No valid pages found to generate techspec.")
            return state
        llm_client = AIService(state["config"].getAiConfig())
        filemanager = state["file_manager"]
        pages = load_visited_pages(filemanager, state["visited_urls"])
        techspec_content = generate_techspec_content(llm_client, pages)
        if techspec_content:
            state["techspec_content"] = techspec_content
            filemanager.update_base_path("output/techspecs/" + state["connector_name"])
            filemanager.write_file("techspec.md", techspec_content)
            console.print("Techspec generation completed.")
        else:
            state["errors"].append(f"Error generating techspec")
    except Exception as e:
        console.print(f"Exception occurred during techspec generation: {e}")
    return state
