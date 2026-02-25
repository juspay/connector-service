from src.ai.system import prompt_config
from src.utils.research.research_utils import generate_search_queries
from ..states.research_state import WorkflowState
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.ai.ai_service import AIService
from json import JSONDecoder
console = Console()


def generate_queries(state: WorkflowState) -> WorkflowState:
   try:
      query = state["query"]
      llm_client = AIService(state["config"].getAiConfig())
      with Progress(SpinnerColumn(), TextColumn("search queries..."), console=console) as progress:
         progress.add_task("[cyan]search queries...", total=1)
         result, success, error = generate_search_queries(connector_name=query, llm_client=llm_client)
         if success:
            state["queries"].append(JSONDecoder().decode(result))
         else:
            state["errors"].append(f"Error creating queries: {error}")
         progress.update(0, advance=1)
         progress.stop()
   except Exception as e:
      state["errors"].append(f"Error creating queries: {str(e)}")

   return state