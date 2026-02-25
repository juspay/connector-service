import click
from typing import List
from ..states.pr_state import PRWorkflowState, PRComment
from src.ai.ai_service import AIService
from src.ai.system.prompt_config import prompt_config


def _format_files_changed(files_changed: List[dict]) -> str:
    if not files_changed:
        return "No files changed information available."

    formatted = []
    for file_info in files_changed:
        additions = file_info.get('additions', 0)
        deletions = file_info.get('deletions', 0)
        changes = file_info.get('changes', 0)
        path = file_info.get('path', 'unknown')

        formatted.append(f"- `{path}` (+{additions}, -{deletions}, ~{changes})")

    return "\n".join(formatted)


def _format_comments(comments: List[PRComment]) -> str:
    if not comments:
        return "No comments available."

    formatted = []
    for comment in comments:
        user = comment.get('user', 'unknown')
        body = comment.get('body', '')
        path = comment.get('path')
        line = comment.get('line')

        if path and line:
            formatted.append(f"**@{user}** on `{path}:{line}`:\n{body}\n")
        else:
            formatted.append(f"**@{user}**:\n{body}\n")

    return "\n---\n".join(formatted)


def analyze_pr(state: PRWorkflowState) -> PRWorkflowState:
    try:
        verbose = state.get('verbose', False)

        if verbose:
            click.echo(f"\n{'='*60}")
            click.echo("Analyzing PR with AI")
            click.echo(f"{'='*60}\n")

        ai_service = AIService()

        pr_prompts = prompt_config(promptfile="pr_prompts.yaml")

        system_prompt = pr_prompts.get("prAnalysisSystemPrompt")

        files_changed_text = _format_files_changed(state.get('pr_files_changed', []))
        review_comments_text = _format_comments(state.get('review_comments', []))
        issue_comments_text = _format_comments(state.get('issue_comments', []))
        metadata_prompt = pr_prompts.get_with_values("prAnalysisMetadataPrompt", {
            "pr_title": state.get('pr_title', ''),
            "pr_body": state.get('pr_body', '') or "No description provided.",
            "pr_author": state.get('pr_author', 'unknown'),
            "repository": f"{state.get('repo_owner', 'unknown')}/{state.get('repo_name', 'unknown')}",
            "pr_number": str(state.get('pr_number', 0)),
            "pr_state": state.get('pr_state', 'unknown'),
            "files_count": str(len(state.get('pr_files_changed', []))),
            "files_changed": files_changed_text,
            "review_comments_count": str(len(state.get('review_comments', []))),
            "review_comments": review_comments_text,
            "issue_comments_count": str(len(state.get('issue_comments', []))),
            "issue_comments": issue_comments_text
        })

        diff_prompt = pr_prompts.get_with_values("prAnalysisDiffPrompt", {
            "pr_diff": state.get('pr_diff', 'No diff available.')
        })

        if verbose:
            click.echo("Sending PR data to AI for analysis...")
            click.echo(f"  • Files changed: {len(state.get('pr_files_changed', []))}")
            click.echo(f"  • Review comments: {len(state.get('review_comments', []))}")
            click.echo(f"  • Issue comments: {len(state.get('issue_comments', []))}")
            click.echo()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": metadata_prompt},
            {"role": "user", "content": diff_prompt}
        ]

        ai_summary, success, error = ai_service.generate(messages)

        if not success:
            error_msg = f"AI analysis failed: {error}"
            click.echo(f"Error: {error_msg}", err=True)
            if 'errors' not in state:
                state['errors'] = []
            state['errors'].append(error_msg)
            state['ai_summary'] = None
        else:
            state['ai_summary'] = ai_summary

            if verbose:
                click.echo(f"{'='*60}")
                click.echo("AI analysis completed successfully!")
                click.echo(f"{'='*60}\n")
                click.echo("Summary preview (first 500 chars):")
                click.echo(ai_summary[:500] + "..." if len(ai_summary) > 500 else ai_summary)
                click.echo()

    except Exception as e:
        error_msg = f"Failed to analyze PR: {str(e)}"
        click.echo(f"Error: {error_msg}", err=True)

        if 'errors' not in state:
            state['errors'] = []
        state['errors'].append(error_msg)
        state['ai_summary'] = None

    return state
