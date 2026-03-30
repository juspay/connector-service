"""Entry point: python -m services.dashboard"""

import sys
from pathlib import Path

import click
from aiohttp import web

from .server import create_app
from ..pr_resolver.config import PRResolverConfig


@click.command()
@click.option("--repo-path", required=True, type=click.Path(exists=True), help="Path to local repo checkout")
@click.option("--github-repo", required=True, help="GitHub repo in owner/repo format")
@click.option("--port", default=8080, type=int, help="Dashboard port")
@click.option("--interval", default=300, type=int, help="Poll interval in seconds")
@click.option("--trigger", default="@10xGrace", help="Trigger tag")
@click.option("--index-dir", default="./index_store", type=click.Path(), help="Index store directory")
@click.option("--state-file", default="./state.json", type=click.Path(), help="State file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(repo_path, github_repo, port, interval, trigger, index_dir, state_file, verbose):
    """10xGrace Dashboard — web UI for the PR comment resolver.

    Starts both the dashboard web server and the PR resolver service.
    Open http://localhost:PORT in your browser.
    """
    config = PRResolverConfig.from_env(
        repo_path=repo_path,
        github_repo=github_repo,
        poll_interval=interval,
        trigger_tag=trigger,
        index_dir=index_dir,
        state_file=state_file,
        verbose=verbose,
    )

    app = create_app(config)

    click.echo(f"10xGrace Dashboard starting on http://localhost:{port}")
    click.echo(f"  Repo: {config.repo_path}")
    click.echo(f"  GitHub: {config.github_repo}")
    click.echo(f"  Trigger: {config.trigger_tag}")
    click.echo(f"  Poll interval: {config.poll_interval}s")
    click.echo()

    web.run_app(app, host="0.0.0.0", port=port, print=None)


if __name__ == "__main__":
    main()
