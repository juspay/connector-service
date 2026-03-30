"""CLI entry point for the PR Resolver service."""

import asyncio
import logging
from pathlib import Path

import click

from .config import PRResolverConfig
from .service import PRResolverService


@click.command("pr-resolver")
@click.option("--repo-path", type=click.Path(exists=True, path_type=Path), default=None, help="Path to the repo checkout.")
@click.option("--github-repo", type=str, default=None, help="GitHub repo in owner/name format.")
@click.option("--interval", type=int, default=None, help="Poll interval in seconds.")
@click.option("--trigger", type=str, default=None, help="Trigger tag (default: @10xGrace).")
@click.option("--max-comments", type=int, default=None, help="Max comments per cycle.")
@click.option("--index-dir", type=click.Path(path_type=Path), default=None, help="Path to the codebase index.")
@click.option("--state-file", type=click.Path(path_type=Path), default=None, help="Path to the state JSON file.")
@click.option("--once", is_flag=True, default=False, help="Run a single cycle and exit.")
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose logging.")
def main(
    repo_path: Path | None,
    github_repo: str | None,
    interval: int | None,
    trigger: str | None,
    max_comments: int | None,
    index_dir: Path | None,
    state_file: Path | None,
    once: bool,
    verbose: bool,
) -> None:
    """Poll GitHub for @10xGrace-tagged review comments and resolve them."""
    overrides = {}
    if repo_path is not None:
        overrides["repo_path"] = repo_path
    if github_repo is not None:
        overrides["github_repo"] = github_repo
    if interval is not None:
        overrides["poll_interval"] = interval
    if trigger is not None:
        overrides["trigger_tag"] = trigger
    if max_comments is not None:
        overrides["max_comments_per_cycle"] = max_comments
    if index_dir is not None:
        overrides["index_dir"] = index_dir
    if state_file is not None:
        overrides["state_file"] = state_file
    if verbose:
        overrides["verbose"] = True

    config = PRResolverConfig.from_env(**overrides)

    # Configure logging
    level = logging.DEBUG if config.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    service = PRResolverService(config)

    if once:
        asyncio.run(service.run_once())
    else:
        asyncio.run(service.run_forever())


if __name__ == "__main__":
    main()
