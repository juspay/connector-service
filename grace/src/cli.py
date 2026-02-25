#!/usr/bin/env python3
"""Grace CLI - Command line interface with research and techspec commands."""

import sys
import asyncio
import click
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import workflow modules
from .workflows import run_techspec_workflow, run_research_workflow, run_pr_workflow
from .config import get_config
from .scripts.searxng_setup import setup_docker, setup_local, check_docker
from .ai.ai_service import AIService
from .grace_test_workflow import run_workflow

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """ Grace CLI - Intelligent research and technical specification generator.\n
        usage:\n
        grace techspec [OPTIONS] [CONNECTOR]\n
        options:\n
            --output TEXT            Output directory for generated specs\n
            --verbose                Enable verbose output\n
            --mock-server or -m      Enable mock server\n
        grace research [OPTIONS] [QUERY]\n
        options:\n
            --output TEXT            Output file path\n
            --tech-spec              Generate technical specification\n
            --format [markdown|json|text]  Output format\n
            --depth INTEGER          Research depth (1-10)\n
            --sources INTEGER        Number of sources to analyze\n
            --verbose                Enable verbose output\n
        grace pr [OPTIONS] [PR_URL]\n
        options:\n
            --output TEXT            Output directory for PR data\n
            --verbose                Enable verbose output\n
    """
    pass


@cli.command()
@click.option('--local', '-l', is_flag=True, help='Use local installation instead of Docker')
def setupsearch(local):
    """Setup SearXNG search engine for Grace Research."""
    if local:
        setup_local()
    elif check_docker():
        setup_docker()
    else:
        setup_local()

@cli.command()
@click.argument('connector', required=False)
@click.option('folder', '-f', help="the docs folder")
@click.option('urls', '-u', help="the docs urls file")
@click.option('--output', '-o', help='Output directory for generated specs')
@click.option('--test-only', is_flag=True, help='Run in test mode without generating files')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--mock-server', '-m', is_flag=True, help='Enable mock server for API interactions (for testing)')
def techspec(connector, folder, urls, output, test_only, verbose, mock_server):
    # we will use the other flags in future for more customization don't remove them
    """ -m flag to mock server and use --help for more details
    -u pass the urls file for docs
    -f pass the docs folder
    """
    async def run_techspec():
        """Async wrapper for techspec workflow."""
        try:
            if verbose:
                click.echo(f"Starting techspec workflow...")
                click.echo(f"Connector: {connector}")
                if output:
                    click.echo(f"Output dir: {output}")
                if mock_server:
                    click.echo("Mock server: ENABLED")
                if test_only:
                    click.echo("Mode: TEST ONLY")
                click.echo()

            if urls:
                click.echo(f"Docs URLs file: {urls}")
            # Use config for output directory if not specified
            output_dir = output or None
            # Execute the techspec workflow
            result = await run_techspec_workflow(
                connector_name=connector,
                folder=folder,
                urls_file=urls,
                output_dir=output_dir,
                test_only=test_only,
                verbose=verbose,
                mock_server=mock_server,
            )

            if result["success"]:
                click.echo("Techspec generation completed successfully!")

                # Display output summary
                output_data = result.get("output", {})
                if output_data:
                    click.echo("\nGeneration Summary:")
                    click.echo(f"  • Connector: {output_data.get('connector_name', connector)}")

                    summary = output_data.get("summary", {})
                    if summary:
                        click.echo(f"  • Total files: {summary.get('total_files', 0)}")
                        click.echo(f"  • Code files: {summary.get('code_files', 0)}")
                        click.echo(f"  • Test files: {summary.get('test_files', 0)}")
                        click.echo(f"  • Documentation: {summary.get('documentation_files', 0)}")

                    output_dir_path = output_data.get("output_directory", f"./generated/{connector}")
                    if not test_only:
                        click.echo(f"  • Output directory: {output_dir_path}")

                        # Create output directory and files (in real implementation)
                        output_path = Path(output_dir_path)
                        output_path.mkdir(parents=True, exist_ok=True)

                        # Save a summary file
                        summary_file = output_path / "generation_summary.json"
                        import json
                        with open(summary_file, 'w') as f:
                            json.dump(result, f, indent=2, default=str)

                        click.echo(f"  • Summary saved: {summary_file}")

                    instructions = output_data.get("instructions", {})
                    if instructions:
                        click.echo("\nNext Steps:")
                        for step in instructions.get("next_steps", []):
                            click.echo(f"  • {step}")

                        if not test_only:
                            test_cmd = instructions.get("test_command")
                            build_cmd = instructions.get("build_command")
                            if test_cmd:
                                click.echo(f"\nTest command: {test_cmd}")
                            if build_cmd:
                                click.echo(f"Build command: {build_cmd}")

            else:
                # click.echo(f"result: {result}")
                if verbose and result.get("metadata"):
                    click.echo(f"Debug info: {result['metadata']}", err=True)
                sys.exit(1)

        except Exception as e:
            click.echo(f"Unexpected error: {str(e)}", err=True)
            if verbose:
                import traceback
                click.echo(f"Traceback: {traceback.format_exc()}", err=True)
            sys.exit(1)

    # Run the async workflow
    asyncio.run(run_techspec())

@cli.command()
@click.argument('query', required=False)
@click.option('--output', '-o', help='Output file path')
@click.option('--tech-spec', '-ts', is_flag=True, help='Generate technical specification')
@click.option('--format', '-f', type=click.Choice(['markdown', 'json', 'text']),
              help='Output format')
@click.option('--depth', '-d', type=int, help='Research depth (1-10)')
@click.option('--ai-browser', '-ai', is_flag=True, help='Enable AI assistance')
@click.option('--sources', '-s', type=int, help='Number of sources to analyze')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def research(query, output, tech_spec, format, depth, ai_browser, sources, verbose):
    """Perform research on a given connector."""
    while not query or query.strip() == "":
        query = click.prompt("Enter your research query: ", type=str, default="", show_default=False)
        if not query:
            click.echo("Error: Research query is required", err=True)
            continue

    async def run_research():
        """Async wrapper for research workflow."""
        try:
            if verbose:
                click.echo(f"Starting research workflow...")
                click.echo(f"Query: {query}")
                if output:
                    click.echo(f"Output file: {output}")
                if tech_spec:
                    click.echo("Technical specification generation: ENABLED")
                if format:
                    click.echo(f"Output format: {format}")
                if depth:
                    click.echo(f"Research depth: {depth}")
                if sources:
                    click.echo(f"Number of sources: {sources}")
                if ai_browser:
                    click.echo("AI assistance: ENABLED")
                click.echo()

            # Use config for output file if not specified
            config_instance = get_config()
            output_file = output or config_instance.getTechSpecConfig().output_dir

            # Execute the research workflow 
            result = await run_research_workflow(
                connector_name=query,
                output_dir=output_file,
                tech_spec=tech_spec,
                format=format,
                depth=depth,
                ai_browser=ai_browser,
                sources=sources,
                verbose=verbose
            )
            click.echo(f"Research result: {result}")
        except Exception as e:
            click.echo(f"Unexpected error: {str(e)}", err=True)
            if verbose:
                import traceback
                click.echo(f"Traceback: {traceback.format_exc()}", err=True)
            sys.exit(1)
        

    asyncio.run(run_research())


@cli.command()
@click.argument('pr_url', required=False)
@click.option('--output', '-o', help='Output directory for PR data')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def pr(pr_url, output, verbose):
    """Fetches PR and summarizes changes using AI."""
    while not pr_url or pr_url.strip() == "":
        pr_url = click.prompt(
            "Enter GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)",
            type=str,
            default="",
            show_default=False
        )
        if not pr_url:
            click.echo("Error: PR URL is required", err=True)
            continue

    async def run_pr():
        try:
            if verbose:
                click.echo(f"Starting PR workflow...")
                click.echo(f"PR URL: {pr_url}")
                if output:
                    click.echo(f"Output directory: {output}")
                click.echo()

            config_instance = get_config()
            output_dir = output or config_instance.getTechSpecConfig().output_dir

            result = await run_pr_workflow(
                pr_url=pr_url,
                output_dir=output_dir,
                verbose=verbose
            )

            if result["success"]:
                output_data = result.get("output", {})
                if output_data:
                    connector_name = output_data.get('connector_name')
                    if connector_name and connector_name != 'unknown':
                        click.echo(f"  • Connector: {connector_name}")

                    stats = output_data.get("statistics", {})
                    if stats:
                        click.echo(f"\n  Statistics:")
                        click.echo(f"    - Files changed: {stats.get('files_changed', 0)}")
                        click.echo(f"    - Total comments: {stats.get('total_comments', 0)}")
                        click.echo(f"      • Review comments (inline): {stats.get('review_comments', 0)}")
                        click.echo(f"      • Issue comments (general): {stats.get('issue_comments', 0)}")

                    # Show AI summary status
                    if output_data.get('has_ai_summary'):
                        click.echo(f"\n  ✓ AI analysis completed")

                    # Show storage locations
                    grace_dir = output_data.get("grace_storage_directory")
                    summary_file = output_data.get("summary_file")

                    click.echo(f"\n  Storage Locations:")
                    if grace_dir:
                        click.echo(f"    - Raw data: {grace_dir}")
                    if summary_file:
                        click.echo(f"    - AI summary: {summary_file}")

            else:
                click.echo(f"PR workflow failed: {result['error']}", err=True)
                if verbose and result.get("metadata"):
                    click.echo(f"Debug info: {result['metadata']}", err=True)
                sys.exit(1)

        except Exception as e:
            click.echo(f"Unexpected error: {str(e)}", err=True)
            if verbose:
                import traceback
                click.echo(f"Traceback: {traceback.format_exc()}", err=True)
            sys.exit(1)

    asyncio.run(run_pr())


@cli.command()
@click.argument('connector_name', required=True)
@click.option('--env', '-e', default='.env.grpc', help='Environment file for gRPC configuration')
@click.option('--test-set', '-t', help='Run specific test set by name')
@click.option('--output-dir', '-o', help='Output directory for results (default: ./output/grpc-results)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def gtest_full(connector_name, env, test_set, output_dir, verbose):
    """Generate gRPC curls, execute tests, and analyze with Claude AI."""

    async def run_complete_test():
        try:
            if verbose:
                click.echo(f"🚀 Running complete test workflow for: {connector_name}")
                click.echo(f"Environment: {env}")
                if test_set:
                    click.echo(f"Test set: {test_set}")
                click.echo()

            # Prepare workflow arguments
            workflow_args = {
                "connector_name": connector_name,
                "env_file": env,
                "test_set": test_set,
                "output_dir": output_dir
            }

            # Run the complete workflow
            results = await run_workflow(workflow_args)

            # Display summary
            test_exec = results.get("workflow_steps", {}).get("test_execution", {})

            if test_exec.get("success"):
                click.echo("\n✅ Tests completed successfully!")
            else:
                click.echo("\n❌ Some tests failed")
                if test_exec.get("stderr"):
                    click.echo(f"\nError: {test_exec['stderr'][-200:]}")

            # Show output files
            output_files = results.get("output_files", {})
            if output_files:
                click.echo("\n📁 Generated files:")
                for file_type, file_path in output_files.items():
                    click.echo(f"  {file_type}: {file_path}")

            # Exit with appropriate code
            sys.exit(0 if test_exec.get("success") else 1)

        except Exception as e:
            click.echo(f"❌ Workflow error: {str(e)}", err=True)
            if verbose:
                import traceback
                click.echo(traceback.format_exc(), err=True)
            sys.exit(1)

    # Run the async workflow
    asyncio.run(run_complete_test())


def main():
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
