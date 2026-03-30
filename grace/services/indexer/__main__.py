"""
CLI entry point for the Grace indexer service.

Usage:
    python -m grace.services.indexer --repo-path /path/to/repo
"""

import click

from .indexer import run_indexer


@click.command()
@click.option("--repo-path", required=True, help="Path to the Rust repository root.")
@click.option("--output", "-o", default=".grace_index", help="Output directory for index data.")
@click.option("--full", is_flag=True, default=False, help="Force a full reindex.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose output.")
@click.option("--no-llm", is_flag=True, default=False, help="Skip LLM summary generation.")
def main(repo_path, output, full, verbose, no_llm):
    """Run the Grace indexer on a Rust codebase."""
    ai_service = None
    if not no_llm:
        try:
            from grace.config import AIService
            ai_service = AIService()
        except ImportError:
            if verbose:
                click.echo("AIService not available, skipping LLM summary.")

    result = run_indexer(
        repo_path=repo_path,
        output_dir=output,
        force_full=full,
        verbose=verbose,
        ai_service=ai_service,
    )

    if result.success:
        click.echo(f"Indexing complete!")
        click.echo(f"  Files parsed: {result.files_parsed}")
        click.echo(f"  Structs: {result.structs_found}")
        click.echo(f"  Enums: {result.enums_found}")
        click.echo(f"  Traits: {result.traits_found}")
        click.echo(f"  Impl blocks: {result.impl_blocks_found}")
        click.echo(f"  Functions: {result.functions_found}")
        if result.meta:
            click.echo(f"  Duration: {result.meta.indexing_duration_seconds}s")
            click.echo(f"  Incremental: {result.meta.incremental}")
    else:
        click.echo("Indexing failed!")
        for err in result.errors:
            click.echo(f"  ERROR: {err}")


if __name__ == "__main__":
    main()
