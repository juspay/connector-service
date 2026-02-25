from typing import Dict, Any, List, Optional, TypedDict
from pathlib import Path
from typing_extensions import TypedDict
from src.tools.filemanager.filemanager import FileManager


class PRComment(TypedDict):
    id: int
    body: str
    user: str
    created_at: str
    updated_at: str
    path: Optional[str]
    line: Optional[int]
    diff_hunk: Optional[str]
    comment_type: str  # 'review', 'issue', 'inline'


class PRMetadata(TypedDict, total=False):
    start_time: float
    end_time: float
    duration: float
    total_comments: int
    review_comments: int
    issue_comments: int
    workflow_started: bool
    timestamp: str


class PRWorkflowState(TypedDict, total=False):
    # Configuration
    output_dir: Path
    verbose: bool
    file_manager: FileManager

    # Input data
    pr_url: str
    repo_owner: str
    repo_name: str
    pr_number: int

    # PR data
    pr_title: str
    pr_body: str
    pr_state: str
    pr_author: str
    pr_created_at: str
    pr_diff: str
    pr_files_changed: List[Dict[str, Any]]

    # Comments data
    comments: List[PRComment]
    review_comments: List[PRComment]
    issue_comments: List[PRComment]

    # Processing results
    stored_files: List[Path]
    connector_name: Optional[str]
    ai_summary: Optional[str]

    # Error tracking
    errors: List[str]
    warnings: List[str]
    error: Optional[str]

    # Workflow metadata
    metadata: PRMetadata

    # Output
    final_output: Dict[str, Any]
