"""Configuration for the PR Resolver service."""

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PRResolverConfig:
    """Configuration for the PR Resolver service."""

    repo_path: Path
    github_repo: str  # e.g. "juspay/hyperswitch-prism"
    poll_interval: int = 300
    trigger_tag: str = "@HS-prism-bot"
    max_comments_per_cycle: int = 10
    state_file: Path = field(default_factory=lambda: Path.home() / ".grace" / "pr_resolver_state.json")
    index_dir: Path = field(default_factory=lambda: Path.home() / ".grace" / "index")
    lock_file: Path = field(default_factory=lambda: Path.home() / ".grace" / "pr_resolver.lock")
    clone_dir: Path = field(default_factory=lambda: Path.home() / ".grace" / "clones")
    max_concurrent_prs: int = 3
    repo_clone_url: str = ""  # Auto-derived from github_repo if empty
    max_build_fix_loops: int = 3
    verbose: bool = False

    @property
    def owner(self) -> str:
        return self.github_repo.split("/")[0]

    @property
    def repo(self) -> str:
        return self.github_repo.split("/")[1]

    def __post_init__(self):
        """Auto-derive repo_clone_url from github_repo if not set."""
        if not self.repo_clone_url:
            self.repo_clone_url = f"https://github.com/{self.github_repo}.git"

    @classmethod
    def from_env(cls, **overrides) -> "PRResolverConfig":
        """Load configuration from environment variables with PR_RESOLVER_ prefix.

        Any keyword arguments override the environment values.
        """
        prefix = "PR_RESOLVER_"

        repo_path = overrides.get(
            "repo_path",
            Path(os.environ.get(f"{prefix}REPO_PATH", os.getcwd())),
        )
        github_repo = overrides.get(
            "github_repo",
            os.environ.get(f"{prefix}GITHUB_REPO", "juspay/hyperswitch-prism"),
        )
        poll_interval = overrides.get(
            "poll_interval",
            int(os.environ.get(f"{prefix}POLL_INTERVAL", "300")),
        )
        trigger_tag = overrides.get(
            "trigger_tag",
            os.environ.get(f"{prefix}TRIGGER_TAG", "@10xGrace"),
        )
        max_comments_per_cycle = overrides.get(
            "max_comments_per_cycle",
            int(os.environ.get(f"{prefix}MAX_COMMENTS_PER_CYCLE", "10")),
        )
        state_file = overrides.get(
            "state_file",
            Path(os.environ.get(f"{prefix}STATE_FILE", str(Path.home() / ".grace" / "pr_resolver_state.json"))),
        )
        index_dir = overrides.get(
            "index_dir",
            Path(os.environ.get(f"{prefix}INDEX_DIR", str(Path.home() / ".grace" / "index"))),
        )
        lock_file = overrides.get(
            "lock_file",
            Path(os.environ.get(f"{prefix}LOCK_FILE", str(Path.home() / ".grace" / "pr_resolver.lock"))),
        )
        clone_dir = overrides.get(
            "clone_dir",
            Path(os.environ.get(f"{prefix}CLONE_DIR", str(Path.home() / ".grace" / "clones"))),
        )
        max_concurrent_prs = overrides.get(
            "max_concurrent_prs",
            int(os.environ.get(f"{prefix}MAX_CONCURRENT", "3")),
        )
        repo_clone_url = overrides.get(
            "repo_clone_url",
            os.environ.get(f"{prefix}REPO_CLONE_URL", ""),  # Empty = auto-derive from github_repo
        )
        max_build_fix_loops = overrides.get(
            "max_build_fix_loops",
            int(os.environ.get(f"{prefix}MAX_BUILD_LOOPS", "3")),
        )
        verbose = overrides.get(
            "verbose",
            os.environ.get(f"{prefix}VERBOSE", "").lower() in ("1", "true", "yes"),
        )

        return cls(
            repo_path=Path(repo_path) if isinstance(repo_path, str) else repo_path,
            github_repo=github_repo,
            poll_interval=poll_interval,
            trigger_tag=trigger_tag,
            max_comments_per_cycle=max_comments_per_cycle,
            state_file=Path(state_file) if isinstance(state_file, str) else state_file,
            index_dir=Path(index_dir) if isinstance(index_dir, str) else index_dir,
            lock_file=Path(lock_file) if isinstance(lock_file, str) else lock_file,
            clone_dir=Path(clone_dir) if isinstance(clone_dir, str) else clone_dir,
            max_concurrent_prs=max_concurrent_prs,
            repo_clone_url=repo_clone_url,
            max_build_fix_loops=max_build_fix_loops,
            verbose=verbose,
        )
