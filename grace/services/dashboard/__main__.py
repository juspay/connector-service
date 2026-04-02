"""Entry point: python -m services.dashboard"""

import sys
from pathlib import Path

import click
from aiohttp import web

from .server import create_app
from ..pr_resolver.config import PRResolverConfig


@click.command()
@click.option("--repo-path", required=True, type=click.Path(exists=True), help="Path to local repo checkout (for index)")
@click.option("--github-repo", required=True, help="GitHub repo in owner/repo format")
@click.option("--port", default=8080, type=int, help="Dashboard port")
@click.option("--interval", default=300, type=int, help="Poll interval in seconds")
@click.option("--trigger", default="@HS-prism-bot", help="Trigger tag")
@click.option("--index-dir", default="./index_store", type=click.Path(), help="Index store directory")
@click.option("--state-file", default="./state.json", type=click.Path(), help="State file path")
@click.option("--clone-dir", default=None, type=click.Path(), help="Clone pool directory (default: ~/.grace/clones)")
@click.option("--max-concurrent", default=3, type=int, help="Max concurrent PRs (clone slots)")
@click.option("--repo-clone-url", default=None, help="Git URL to clone (default: 10xGRACE/connector-service)")
@click.option("--max-build-loops", default=3, type=int, help="Max build-fix loop iterations")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(repo_path, github_repo, port, interval, trigger, index_dir, state_file, clone_dir, max_concurrent, repo_clone_url, max_build_loops, verbose):
    """10xGrace Dashboard — web UI for the PR comment resolver.

    Starts both the dashboard web server and the PR resolver service.
    Open http://localhost:PORT in your browser.
    """
    overrides = dict(
        repo_path=repo_path,
        github_repo=github_repo,
        poll_interval=interval,
        trigger_tag=trigger,
        index_dir=index_dir,
        state_file=state_file,
        max_concurrent_prs=max_concurrent,
        max_build_fix_loops=max_build_loops,
        verbose=verbose,
    )
    if clone_dir:
        overrides["clone_dir"] = clone_dir
    if repo_clone_url:
        overrides["repo_clone_url"] = repo_clone_url

    config = PRResolverConfig.from_env(**overrides)
    app = create_app(config)

    click.echo(f"10xGrace Dashboard starting on http://localhost:{port}")
    click.echo(f"  Repo: {config.repo_path}")
    click.echo(f"  GitHub: {config.github_repo}")
    click.echo(f"  Clone URL: {config.repo_clone_url}")
    click.echo(f"  Clone dir: {config.clone_dir}")
    click.echo(f"  Max concurrent: {config.max_concurrent_prs}")
    click.echo(f"  Trigger: {config.trigger_tag}")
    click.echo(f"  Poll interval: {config.poll_interval}s")
    click.echo(f"  Build-fix loops: {config.max_build_fix_loops}")
    click.echo()

    web.run_app(app, host="0.0.0.0", port=port, print=None)


if __name__ == "__main__":
    main()
