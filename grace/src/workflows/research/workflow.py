from typing import Dict, Any, Literal, Optional
from pathlib import Path
from src.tools.filemanager.filemanager import FileManager
from src.config import get_config
from langgraph.graph import StateGraph, START, END
from .states.research_state import WorkflowState
from datetime import datetime
from rich.console import Console
from .nodes import generate_queries,search_and_verify_queries, scrap_links_and_analyse_pages, techspec_generation

console = Console()
class ResearchWorkflow:

    def __init__(self):
        self.graph = self._build_workflow_graph()

    def _build_workflow_graph(self):

        # Create state graph
        workflow = StateGraph(WorkflowState)

        # Add nodes for each step
        workflow.add_node("generate_queries", generate_queries)
        workflow.add_node("search_and_verify_queries", search_and_verify_queries)
        workflow.add_node("scrap_links_and_analyse_pages", scrap_links_and_analyse_pages)
        workflow.add_node("techspec_generation", techspec_generation)
        workflow.add_node("end", lambda state: state)

        # Define conditions for branching
        workflow.add_edge(
            START,
            "generate_queries"
        )
        workflow.add_edge("generate_queries", "search_and_verify_queries")

        workflow.add_conditional_edges(
            "search_and_verify_queries",
            self._should_continue_after_verify_links,
            {
                "scrap_links_and_analyse_pages": "scrap_links_and_analyse_pages",
                "end": "end"
            }
        )
        workflow.add_conditional_edges(
            "scrap_links_and_analyse_pages",
            self._should_continue_after_analyse_pages,
            {
                "techspec_generation": "techspec_generation",
                "end": "end"
            }
        )
        workflow.add_edge("techspec_generation", "end")
        workflow.add_edge("end", END)

        # Compile the graph
        return workflow.compile()
    def _should_continue_after_input(self, state: WorkflowState) -> Literal["input_node", "generate_queries"]:
        return "input_node"

    def _should_continue_after_verify_links(self, state: WorkflowState) -> Literal["scrap_links_and_analyse_pages", "end"]:
        if state["search_results"]:
            return "scrap_links_and_analyse_pages"
        return "end"
    def _should_continue_after_analyse_pages(self, state: WorkflowState) -> Literal["techspec_generation", "end"]:
        if state["visited_urls"]:
            return "techspec_generation"
        return "end"

    def _should_continue_after_techspec_generation(self, state: WorkflowState) -> Literal["mock_server", "end"]:
        return "mock_server"
     
    async def execute(self,
                     connector_name: str,
                     output_dir: Optional[str] = None,
                     tech_spec: bool = False,
                     format: Optional[str] = None,
                     depth: Optional[int] = None,
                     ai_browser: bool = False,
                     sources: Optional[int] = None,
                     verbose: bool = False
    ) -> Dict[str, Any]:
        global_config = get_config()
        techspec_config = global_config.getTechSpecConfig()
        # Convert output_dir to Path object
        output_path = Path(output_dir) if output_dir else Path(techspec_config.output_dir)

        # Initialize state
        initial_state: WorkflowState = {
            "connector_name": connector_name,
            "query": connector_name,
            "format": format or "markdown",
            "file_manager": FileManager(".grace/research/scraped_pages/"),
            "depth": depth or 10,
            "ai_browser": ai_browser,
            "sources": sources or [],
            "tech_spec": tech_spec,
            "queries": [],
            "search_results": [],
            "visited_urls": [],
            "output_dir": output_path,
            "config": global_config,
            "verbose": verbose,
            "final_output": {},
            "validation_results": None,
            "error": None,
            "errors": [],
            "metadata": {
                "workflow_started": True, 
                "timestamp": datetime.now().isoformat()
                },
        }

        try:
            # Execute the workflow graph
            result = await self.graph.ainvoke(initial_state)

            return {
                "success": result["error"] is None,
                "connector_name": result["connector_name"],
                "output": result["final_output"],
                "metadata": result["metadata"],
                "techspec_content": result.get("techspec_content", "")[:200],
                "error": result["error"],
                "errors": result["errors"],
                "validation_status": result["validation_results"]["overall_status"] if result["validation_results"] else "unknown",
                "files_generated": result["final_output"].get("summary", {}).get("total_files", 0) if result["final_output"] else 0
            }

        except Exception as e:
            return {
                "success": False,
                "connector_name": connector_name,
                "output": {},
                "metadata": {"error": str(e), "workflow_failed": True},
                "error": str(e),
                "validation_status": "failed",
                "files_generated": 0
            }
        
class SearchWorkflow:
    pass



def create_research_workflow() -> WorkflowState:
    return ResearchWorkflow()


async def run_research_workflow(connector_name: str,
                               output_dir: Optional[str] = None,
                               tech_spec: bool = False,
                               format: Optional[str] = None,
                               depth: Optional[int] = None,
                               ai_browser: bool = False,
                               sources: Optional[int] = None,
                               verbose: bool = False) -> Dict[str, Any]:
    workflow = create_research_workflow()
    return await workflow.execute(
                connector_name=connector_name,
                output_dir=output_dir,
                tech_spec=tech_spec,
                format=format,
                depth=depth,
                ai_browser=ai_browser,
                sources=sources,
                verbose=verbose
    )

def create_search_workflow() -> SearchWorkflow:
    return SearchWorkflow()

async def run_search_workflow(connector_name: str,
                              output_dir: Optional[str] = None,
                              mock_server: bool = False,
                              test_only: bool = False,
                              verbose: bool = False) -> Dict[str, Any]:
    workflow = create_search_workflow()
    return await workflow.execute(
        connector_name=connector_name,
        output_dir=output_dir,
        mock_server=mock_server,
        test_only=test_only,
        verbose=verbose
    )
