import subprocess
import json
import re
import click
from typing import Dict, Any, List, Optional
from ..states.pr_state import PRWorkflowState, PRComment


def _parse_pr_url(pr_url: str) -> tuple[str, str, int]:
    url_pattern = r'github\.com/([^/]+)/([^/]+)/pull/(\d+)'
    match = re.search(url_pattern, pr_url)

    if match:
        owner, repo, pr_num = match.groups()
        return owner, repo, int(pr_num)

    short_pattern = r'^([^/]+)/([^#]+)#(\d+)$'
    match = re.match(short_pattern, pr_url)

    if match:
        owner, repo, pr_num = match.groups()
        return owner, repo, int(pr_num)

    raise ValueError(f"Invalid PR URL format: {pr_url}")


def _run_gh_command(command: List[str]) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ['gh'] + command,
            capture_output=True,
            text=True,
            check=True
        )

        if result.stdout:
            return json.loads(result.stdout)
        return {}

    except subprocess.CalledProcessError as e:
        error_msg = f"GitHub CLI error: {e.stderr}"
        raise RuntimeError(error_msg)
    except json.JSONDecodeError as e:
        error_msg = f"Failed to parse gh CLI output: {str(e)}"
        raise RuntimeError(error_msg)
    except FileNotFoundError:
        raise RuntimeError(
            "GitHub CLI (gh) not found. Please install it from https://cli.github.com/"
        )


def _fetch_pr_details(owner: str, repo: str, pr_number: int, verbose: bool) -> Dict[str, Any]:
    if verbose:
        click.echo(f"Fetching PR details for {owner}/{repo}#{pr_number}...")

    command = [
        'pr', 'view', str(pr_number),
        '--repo', f'{owner}/{repo}',
        '--json', 'title,body,state,author,createdAt,updatedAt,number'
    ]

    return _run_gh_command(command)


def _fetch_pr_diff(owner: str, repo: str, pr_number: int, verbose: bool) -> str:
    if verbose:
        click.echo(f"Fetching PR diff...")

    try:
        result = subprocess.run(
            ['gh', 'pr', 'diff', str(pr_number), '--repo', f'{owner}/{repo}'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to fetch PR diff: {e.stderr}")


def _fetch_pr_files(owner: str, repo: str, pr_number: int, verbose: bool) -> List[Dict[str, Any]]:
    if verbose:
        click.echo(f"Fetching changed files...")

    command = [
        'pr', 'view', str(pr_number),
        '--repo', f'{owner}/{repo}',
        '--json', 'files'
    ]

    result = _run_gh_command(command)
    return result.get('files', [])


def _fetch_review_comments(owner: str, repo: str, pr_number: int, verbose: bool) -> List[PRComment]:
    if verbose:
        click.echo(f"Fetching review comments...")

    command = [
        'api',
        f'repos/{owner}/{repo}/pulls/{pr_number}/comments',
        '--paginate'
    ]

    comments_data = _run_gh_command(command)

    review_comments = []
    for comment in comments_data:
        review_comments.append({
            'id': comment.get('id'),
            'body': comment.get('body', ''),
            'user': comment.get('user', {}).get('login', 'unknown'),
            'created_at': comment.get('created_at', ''),
            'updated_at': comment.get('updated_at', ''),
            'path': comment.get('path'),
            'line': comment.get('line') or comment.get('original_line'),
            'diff_hunk': comment.get('diff_hunk'),
            'comment_type': 'review'
        })

    return review_comments


def _fetch_issue_comments(owner: str, repo: str, pr_number: int, verbose: bool) -> List[PRComment]:
    if verbose:
        click.echo(f"Fetching issue comments...")

    command = [
        'api',
        f'repos/{owner}/{repo}/issues/{pr_number}/comments',
        '--paginate'
    ]

    comments_data = _run_gh_command(command)

    issue_comments = []
    for comment in comments_data:
        issue_comments.append({
            'id': comment.get('id'),
            'body': comment.get('body', ''),
            'user': comment.get('user', {}).get('login', 'unknown'),
            'created_at': comment.get('created_at', ''),
            'updated_at': comment.get('updated_at', ''),
            'path': None,
            'line': None,
            'diff_hunk': None,
            'comment_type': 'issue'
        })

    return issue_comments


def _extract_connector_name(pr_title: str, pr_body: str) -> Optional[str]:
    # Try to find connector name in title
    title_patterns = [
        r'(?:add|create|implement|update|fix)\s+(\w+)\s+connector',
        r'connector[:\s]+(\w+)',
        r'\[(\w+)\]',
    ]

    for pattern in title_patterns:
        match = re.search(pattern, pr_title, re.IGNORECASE)
        if match:
            return match.group(1).lower()

    # Try to find in body
    if pr_body:
        for pattern in title_patterns:
            match = re.search(pattern, pr_body, re.IGNORECASE)
            if match:
                return match.group(1).lower()

    return None


def fetch_pr_data(state: PRWorkflowState) -> PRWorkflowState:
    try:
        pr_url = state['pr_url']
        verbose = state.get('verbose', False)

        if verbose:
            click.echo(f"\n{'='*60}")
            click.echo("Fetching PR Data")
            click.echo(f"{'='*60}\n")

        # Parse PR URL
        owner, repo, pr_number = _parse_pr_url(pr_url)
        state['repo_owner'] = owner
        state['repo_name'] = repo
        state['pr_number'] = pr_number

        if verbose:
            click.echo(f"Repository: {owner}/{repo}")
            click.echo(f"PR Number: #{pr_number}\n")

        pr_details = _fetch_pr_details(owner, repo, pr_number, verbose)
        state['pr_title'] = pr_details.get('title', '')
        state['pr_body'] = pr_details.get('body', '')
        state['pr_state'] = pr_details.get('state', '')
        state['pr_author'] = pr_details.get('author', {}).get('login', 'unknown')
        state['pr_created_at'] = pr_details.get('createdAt', '')

        if verbose:
            click.echo(f"Title: {state['pr_title']}")
            click.echo(f"State: {state['pr_state']}")
            click.echo(f"Author: {state['pr_author']}\n")

        # Fetch PR diff
        state['pr_diff'] = _fetch_pr_diff(owner, repo, pr_number, verbose)

        # Fetch changed files
        state['pr_files_changed'] = _fetch_pr_files(owner, repo, pr_number, verbose)

        if verbose:
            click.echo(f"Files changed: {len(state['pr_files_changed'])}\n")

        # Fetch comments
        review_comments = _fetch_review_comments(owner, repo, pr_number, verbose)
        issue_comments = _fetch_issue_comments(owner, repo, pr_number, verbose)

        state['review_comments'] = review_comments
        state['issue_comments'] = issue_comments
        state['comments'] = review_comments + issue_comments

        if verbose:
            click.echo(f"Review comments (inline): {len(review_comments)}")
            click.echo(f"Issue comments (general): {len(issue_comments)}")
            click.echo(f"Total comments: {len(state['comments'])}\n")

        # Extract connector name
        connector_name = _extract_connector_name(state['pr_title'], state['pr_body'])
        state['connector_name'] = connector_name

        if verbose and connector_name:
            click.echo(f"Detected connector: {connector_name}\n")

        # Update metadata
        if 'metadata' not in state:
            state['metadata'] = {}

        state['metadata']['total_comments'] = len(state['comments'])
        state['metadata']['review_comments'] = len(review_comments)
        state['metadata']['issue_comments'] = len(issue_comments)

        if verbose:
            click.echo(f"{'='*60}")
            click.echo("PR data fetched successfully!")
            click.echo(f"{'='*60}\n")

    except Exception as e:
        error_msg = f"Failed to fetch PR data: {str(e)}"
        click.echo(f"Error: {error_msg}", err=True)

        if 'errors' not in state:
            state['errors'] = []
        state['errors'].append(error_msg)
        state['error'] = error_msg

    return state
