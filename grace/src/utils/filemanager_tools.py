from src.tools.filemanager.filemanager import FileManager
from .transformations import sanitize_filename

def save_file(result: dict, fileManager: FileManager):
    filename = sanitize_filename(result["url"])
    content = f"""
        # Documentation for {result.get('title', 'No Title')}
        **Source URL:** {result['url']}
        ---
        {result['html_content']}
    """
    fileManager.write_file(filename, content)
    return fileManager.base_path / filename
