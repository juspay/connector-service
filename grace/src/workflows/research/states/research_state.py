from typing import Dict, Any, List, Optional, TypedDict
from pathlib import Path
from subprocess import Popen
from src.tools.filemanager.filemanager import FileManager
from src.config import  TechSpecConfig, Config

class WorkflowState(TypedDict, total=False):
    """State representation for the research workflow."""
    config : Config
    techSpecConfig: TechSpecConfig
    query: str
    connector_name: str
    output_dir: Path
    test_only: bool
    verbose: bool
    generate_techspec: bool
    generate_mockserver: bool

    file_manager: FileManager
    
    # Research workflow fields
    queries: List[List[str]]
    search_results: List[Any]

    urls: List[str]


    visited_urls: List[str]
    valid_pages: List[str]

    scrapping_failed_pages: Optional[List[str]]


    final_output: Dict[str, Any]
    error: Optional[str]
    metadata: Dict[str, Any]
    validation_results: Optional[Dict[str, Any]]
    
    # Techspec generation fields
    techspec_content: Optional[str]
    
    # Mock server generation fields
    mock_server_dir: Optional[Path]
    mock_server_process: Optional[Popen]
    mock_server_data: Optional[Dict[str, Any]]
    
    # Error handling
    errors: List[str]