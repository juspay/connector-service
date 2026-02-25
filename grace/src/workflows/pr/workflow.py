import click
from typing import Dict, Any, Literal, Optional
from pathlib import Path
from src.config import get_config
from src.tools.filemanager.filemanager import FileManager
from langgraph.graph import StateGraph, START, END
from .states.pr_state import PRWorkflowState
from datetime import datetime
from .nodes import fetch_pr_data, analyze_pr, store_pr_data


class PRWorkflow:
    def __init__(self):
        self.graph = self._build_workflow_graph()

    def _build_workflow_graph(self):
        # Create state graph
        workflow = StateGraph(PRWorkflowState)

        # Add nodes for each step
        workflow.add_node("fetch_pr_data", fetch_pr_data)
        workflow.add_node("analyze_pr", analyze_pr)
        workflow.add_node("store_pr_data", store_pr_data)
        workflow.add_node("end", lambda state: state)  # Terminal node

        # Define workflow edges
        workflow.add_edge(START, "fetch_pr_data")

        # Conditional edge after fetching - analyze if no errors
        workflow.add_conditional_edges(
            "fetch_pr_data",
            self._should_continue_after_fetch,
            {
                "analyze_pr": "analyze_pr",
                "end": "end"
            }
        )

        # Always continue to store after analysis (even if AI fails)
        workflow.add_edge("analyze_pr", "store_pr_data")
        workflow.add_edge("store_pr_data", "end")
        workflow.add_edge("end", END)

        # Compile the graph
        return workflow.compile()

    def _should_continue_after_fetch(self, state: PRWorkflowState) -> Literal["analyze_pr", "end"]:
        if state.get('error') or state.get('errors'):
            click.echo("Data fetching failed. Skipping analysis and storage.", err=True)
            return "end"
        return "analyze_pr"

    async def execute(
        self,
        pr_url: str,
        output_dir: Optional[str] = None,
        verbose: bool = False
    ) -> Dict[str, Any]:
        config = get_config().getTechSpecConfig()

        # Convert output_dir to Path object
        output_path = Path(output_dir) if output_dir else Path(config.output_dir)

        # Parse PR URL to get repo and PR number for FileManager path
        # This is a simple parse - will be validated in fetch_pr_data node
        try:
            import re
            match = re.search(r'github\.com/([^/]+)/([^/]+)/pull/(\d+)', pr_url)
            if match:
                repo_name = match.group(2)
                pr_number = match.group(3)
            else:
                # Try short format
                match = re.match(r'^([^/]+)/([^#]+)#(\d+)$', pr_url)
                if match:
                    repo_name = match.group(2)
                    pr_number = match.group(3)
                else:
                    # Default fallback
                    repo_name = "unknown"
                    pr_number = "0"
        except:
            repo_name = "unknown"
            pr_number = "0"

        # Initialize FileManager for .grace/pr/{repo}/{prNumber}/
        file_manager = FileManager(f".grace/pr/{repo_name}/{pr_number}")

        # Initialize state
        initial_state: PRWorkflowState = {
            "pr_url": pr_url,
            "output_dir": output_path,
            "verbose": verbose,
            "file_manager": file_manager,
            "errors": [],
            "warnings": [],
            "error": None,
            "metadata": {
                "workflow_started": True,
                "timestamp": datetime.now().isoformat()
            },
            "stored_files": [],
            "final_output": {}
        }

        try:
            # Execute the workflow graph
            result = await self.graph.ainvoke(initial_state)

            return {
                "success": result.get("error") is None,
                "pr_url": result.get("pr_url"),
                "repository": f"{result.get('repo_owner', '')}/{result.get('repo_name', '')}",
                "pr_number": result.get("pr_number"),
                "connector_name": result.get("connector_name"),
                "output": result.get("final_output", {}),
                "metadata": result.get("metadata", {}),
                "error": result.get("error"),
                "total_comments": len(result.get("comments", [])),
                "files_stored": len(result.get("stored_files", []))
            }

        except Exception as e:
            return {
                "success": False,
                "pr_url": pr_url,
                "repository": "",
                "pr_number": None,
                "connector_name": None,
                "output": {},
                "metadata": {"error": str(e), "workflow_failed": True},
                "error": str(e),
                "total_comments": 0,
                "files_stored": 0
            }


def create_pr_workflow() -> PRWorkflow:
    return PRWorkflow()


async def run_pr_workflow(
    pr_url: str,
    output_dir: Optional[str] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    workflow = create_pr_workflow()
    return await workflow.execute(
        pr_url=pr_url,
        output_dir=output_dir,
        verbose=verbose
    )
