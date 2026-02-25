import json
import click
from pathlib import Path
from typing import List
from ..states.pr_state import PRWorkflowState, PRComment
from src.tools.filemanager.filemanager import FileManager

def _sanitize_filename(name: str) -> str:
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    name = name.strip('. ')
    return name[:200] if name else 'unnamed'


def _store_pr_metadata(file_manager, state: PRWorkflowState, verbose: bool) -> None:
    metadata = {
        'url': state['pr_url'],
        'repository': f"{state['repo_owner']}/{state['repo_name']}",
        'pr_number': state['pr_number'],
        'title': state['pr_title'],
        'body': state['pr_body'],
        'state': state['pr_state'],
        'author': state['pr_author'],
        'created_at': state['pr_created_at'],
        'connector_name': state.get('connector_name'),
        'files_changed_count': len(state.get('pr_files_changed', [])),
        'total_comments': len(state.get('comments', []))
    }

    file_manager.write_file(Path('metadata.json'), json.dumps(metadata, indent=2, ensure_ascii=False))

    if verbose:
        click.echo(f"  ✓ Stored metadata: metadata.json")


def _store_pr_diff(file_manager, state: PRWorkflowState, verbose: bool) -> None:
    file_manager.write_file(Path('diff.patch'), state['pr_diff'])

    if verbose:
        click.echo(f"  ✓ Stored diff: diff.patch")


def _store_changed_files(file_manager, state: PRWorkflowState, verbose: bool) -> None:
    files_data = {
        'total_files': len(state.get('pr_files_changed', [])),
        'files': state.get('pr_files_changed', [])
    }

    file_manager.write_file(
        Path('changed_files.json'),
        json.dumps(files_data, indent=2, ensure_ascii=False)
    )

    if verbose:
        click.echo(f"  ✓ Stored changed files list: changed_files.json")


def _store_comment(
    file_manager,
    comment_type: str,
    comment: PRComment,
    connector_name: str
) -> str:
    comment_id = comment['id']

    # Build filename parts
    filename_parts = [str(comment_id)]

    if connector_name:
        filename_parts.append(connector_name)

    # Add sanitized path if it's a review comment
    if comment.get('path'):
        path_sanitized = _sanitize_filename(comment['path'])
        filename_parts.append(path_sanitized)

    filename = '-'.join(filename_parts) + '.json'

    # Store comment with all metadata
    comment_data = {
        'id': comment['id'],
        'type': comment['comment_type'],
        'user': comment['user'],
        'created_at': comment['created_at'],
        'updated_at': comment['updated_at'],
        'body': comment['body'],
        'path': comment.get('path'),
        'line': comment.get('line'),
        'diff_hunk': comment.get('diff_hunk')
    }

    file_manager.write_file(
        Path('comments') / comment_type / filename,
        json.dumps(comment_data, indent=2, ensure_ascii=False)
    )

    return filename


def _store_comments(file_manager, state: PRWorkflowState, verbose: bool) -> int:
    connector_name = state.get('connector_name', 'unknown')
    files_stored = 0

    # Store review comments
    for comment in state.get('review_comments', []):
        _store_comment(file_manager, 'review', comment, connector_name)
        files_stored += 1

    if verbose and state.get('review_comments'):
        click.echo(
            f"  ✓ Stored {len(state['review_comments'])} review comments in: comments/review/"
        )

    # Store issue comments
    for comment in state.get('issue_comments', []):
        _store_comment(file_manager, 'issue', comment, connector_name)
        files_stored += 1

    if verbose and state.get('issue_comments'):
        click.echo(
            f"  ✓ Stored {len(state['issue_comments'])} issue comments in: comments/issue/"
        )

    return files_stored


def _store_ai_summary(output_dir: Path, file_manager: FileManager, state: PRWorkflowState, verbose: bool) -> Path:
    connector_name = state.get('connector_name', 'unknown')
    repo_name = state['repo_name']
    pr_number = state['pr_number']

    # Create filename: {repo}-{prNumber}-{connector}.md
    summary_filename = f"{repo_name}-{pr_number}"
    if connector_name and connector_name != 'unknown':
        summary_filename += f"-{connector_name}"
    summary_filename += ".md"
    summary_file = output_dir / summary_filename

    ai_summary = state.get('ai_summary', '')
    grace_path = file_manager.base_path

    summary_content = f"""# PR Analysis
**Repository:** {state['repo_owner']}/{state['repo_name']}
**PR Number:** #{state['pr_number']}
**Title:** {state['pr_title']}
**Connector:** {connector_name if connector_name != 'unknown' else 'N/A'}
## Summary
{ai_summary if ai_summary else '*No analysis available*'}

## Raw Data Location

All raw PR data (diff, comments, metadata) is stored in:
```
{grace_path.absolute()}
```
"""
    file_manager.update_base_path(output_dir)
    file_manager.write_file(Path(summary_filename), summary_content)

    if verbose:
        click.echo(f"\n  ✓ Stored AI summary: {summary_file}")
    file_manager.update_base_path(grace_path)
    return summary_file


def store_pr_data(state: PRWorkflowState) -> PRWorkflowState:
    try:
        verbose = state.get('verbose', False)
        file_manager = state['file_manager']
        output_dir = state['output_dir']

        if verbose:
            click.echo(f"\n{'='*60}")
            click.echo("Storing PR Data")
            click.echo(f"{'='*60}\n")
            click.echo(f"Raw data storage: {file_manager.base_path}")
            click.echo(f"Summary storage: {output_dir}\n")

        files_stored_count = 0

        # Store raw data in .grace directory using FileManager
        _store_pr_metadata(file_manager, state, verbose)
        files_stored_count += 1

        _store_pr_diff(file_manager, state, verbose)
        files_stored_count += 1

        _store_changed_files(file_manager, state, verbose)
        files_stored_count += 1

        comment_files_count = _store_comments(file_manager, state, verbose)
        files_stored_count += comment_files_count

        # Store AI summary in output directory (not using FileManager)
        summary_file = _store_ai_summary(output_dir, file_manager, state, verbose)
        files_stored_count += 1

        # Update state
        state['final_output'] = {
            'grace_storage_directory': str(file_manager.base_path),
            'summary_file': str(summary_file),
            'repository': f"{state['repo_owner']}/{state['repo_name']}",
            'pr_number': state['pr_number'],
            'connector_name': state.get('connector_name'),
            'total_files_stored': files_stored_count,
            'has_ai_summary': bool(state.get('ai_summary')),
            'statistics': {
                'total_comments': len(state.get('comments', [])),
                'review_comments': len(state.get('review_comments', [])),
                'issue_comments': len(state.get('issue_comments', [])),
                'files_changed': len(state.get('pr_files_changed', []))
            }
        }

        if verbose:
            click.echo(f"\n{'='*60}")
            click.echo("PR data stored successfully!")
            click.echo(f"{'='*60}\n")

    except Exception as e:
        error_msg = f"Failed to store PR data: {str(e)}"
        click.echo(f"Error: {error_msg}", err=True)

        if 'errors' not in state:
            state['errors'] = []
        state['errors'].append(error_msg)
        state['error'] = error_msg

    return state
