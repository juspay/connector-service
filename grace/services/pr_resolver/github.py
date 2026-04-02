"""GitHub GraphQL client for the PR Resolver service — uses the ``gh`` CLI."""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ReviewComment:
    id: str
    body: str
    author: str
    author_association: str
    created_at: str
    updated_at: str
    diff_hunk: str


@dataclass
class ReviewThread:
    id: str
    is_resolved: bool
    is_outdated: bool
    path: str
    line: Optional[int]
    start_line: Optional[int]
    comments: List[ReviewComment] = field(default_factory=list)


@dataclass
class PRInfo:
    number: int
    title: str
    head_ref: str
    state: str
    author: str
    threads: List[ReviewThread] = field(default_factory=list)


@dataclass
class TriggeredThread:
    thread_id: str
    pr_number: int
    pr_branch: str
    path: str
    line: Optional[int]
    instruction: str
    diff_hunk: str
    author: str
    comment_node_id: str = ""  # For adding reactions (👀)
    author_association: str = "NONE"


# ---------------------------------------------------------------------------
# GraphQL queries
# ---------------------------------------------------------------------------

FETCH_PRS_QUERY = """
query($owner: String!, $repo: String!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequests(states: OPEN, first: 50, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        title
        headRefName
        state
        author { login }
        reviewThreads(first: 100) {
          nodes {
            id
            isResolved
            isOutdated
            path
            line
            startLine
            comments(first: 50) {
              nodes {
                id
                body
                author { login }
                authorAssociation
                createdAt
                updatedAt
                diffHunk
              }
            }
          }
        }
      }
    }
  }
}
"""

FETCH_SINGLE_PR_QUERY = """
query($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      number
      title
      headRefName
      state
      author { login }
      reviewThreads(first: 100) {
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          startLine
          comments(first: 50) {
            nodes {
              id
              body
              author { login }
              createdAt
              updatedAt
              diffHunk
            }
          }
        }
      }
    }
  }
}
"""

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


async def _run_graphql(query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a GraphQL query via ``gh api graphql``."""
    cmd = ["gh", "api", "graphql"]
    cmd += ["-f", f"query={query}"]
    for key, value in variables.items():
        if isinstance(value, int):
            cmd += ["-F", f"{key}={value}"]
        else:
            cmd += ["-f", f"{key}={value}"]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

    if proc.returncode != 0:
        raise RuntimeError(f"gh api graphql failed (rc={proc.returncode}): {stderr.decode(errors='replace')}")

    return json.loads(stdout.decode(errors="replace"))


def _parse_pr_node(node: Dict[str, Any]) -> PRInfo:
    """Convert a raw GraphQL PR node into a ``PRInfo``."""
    threads: List[ReviewThread] = []
    for t in node.get("reviewThreads", {}).get("nodes", []) or []:
        comments: List[ReviewComment] = []
        for c in t.get("comments", {}).get("nodes", []) or []:
            comments.append(
                ReviewComment(
                    id=c["id"],
                    body=c.get("body", ""),
                    author=(c.get("author") or {}).get("login", "unknown"),
                    author_association=c.get("authorAssociation", "NONE"),
                    created_at=c.get("createdAt", ""),
                    updated_at=c.get("updatedAt", ""),
                    diff_hunk=c.get("diffHunk", ""),
                )
            )
        threads.append(
            ReviewThread(
                id=t["id"],
                is_resolved=t.get("isResolved", False),
                is_outdated=t.get("isOutdated", False),
                path=t.get("path", ""),
                line=t.get("line"),
                start_line=t.get("startLine"),
                comments=comments,
            )
        )

    return PRInfo(
        number=node["number"],
        title=node.get("title", ""),
        head_ref=node.get("headRefName", ""),
        state=node.get("state", ""),
        author=(node.get("author") or {}).get("login", "unknown"),
        threads=threads,
    )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class GitHubClient:
    """Thin wrapper around ``gh`` CLI for GitHub API access."""

    def __init__(self, owner: str, repo: str) -> None:
        self.owner = owner
        self.repo = repo

    async def fetch_open_prs_with_threads(self) -> List[PRInfo]:
        """Fetch all open PRs with their review threads (paginated)."""
        prs: List[PRInfo] = []
        cursor: Optional[str] = None

        while True:
            variables: Dict[str, Any] = {"owner": self.owner, "repo": self.repo}
            if cursor:
                variables["cursor"] = cursor

            data = await _run_graphql(FETCH_PRS_QUERY, variables)
            pr_connection = data.get("data", {}).get("repository", {}).get("pullRequests", {})

            for node in pr_connection.get("nodes", []) or []:
                prs.append(_parse_pr_node(node))

            page_info = pr_connection.get("pageInfo", {})
            if page_info.get("hasNextPage"):
                cursor = page_info["endCursor"]
            else:
                break

        return prs

    async def fetch_pr_threads(self, pr_number: int) -> Optional[PRInfo]:
        """Fetch a single PR by number with its review threads."""
        variables: Dict[str, Any] = {
            "owner": self.owner,
            "repo": self.repo,
            "number": pr_number,
        }
        data = await _run_graphql(FETCH_SINGLE_PR_QUERY, variables)
        node = data.get("data", {}).get("repository", {}).get("pullRequest")
        if node is None:
            return None
        return _parse_pr_node(node)

    async def post_thread_reply(self, thread_id: str, body: str) -> bool:
        """Post a reply to a review thread via the ``gh`` CLI REST fallback."""
        # GraphQL addPullRequestReviewComment requires a review; use the
        # REST-compatible mutation instead.
        mutation = """
        mutation($threadId: ID!, $body: String!) {
          addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $threadId, body: $body}) {
            comment { id }
          }
        }
        """
        try:
            await _run_graphql(mutation, {"threadId": thread_id, "body": body})
            return True
        except Exception:
            logger.exception("Failed to post reply to thread %s", thread_id)
            return False

    async def add_reaction(self, comment_node_id: str, reaction: str = "EYES") -> bool:
        """Add a reaction (e.g., EYES 👀) to a comment to signal it's been picked up."""
        mutation = """
        mutation($subjectId: ID!, $content: ReactionContent!) {
          addReaction(input: {subjectId: $subjectId, content: $content}) {
            reaction { content }
          }
        }
        """
        try:
            await _run_graphql(mutation, {"subjectId": comment_node_id, "content": reaction})
            return True
        except Exception:
            logger.debug("Failed to add reaction to %s", comment_node_id)
            return False


# ---------------------------------------------------------------------------
# Trigger filtering
# ---------------------------------------------------------------------------


def filter_triggered_threads(
    pr: PRInfo,
    trigger: str,
    processed_ids: Set[str],
) -> List[TriggeredThread]:
    """Return threads that contain the trigger tag and have not been processed yet.

    The trigger tag is matched case-insensitively.  If the tag appears in a
    reply (not the root comment) the instruction is still extracted from that
    comment; the path/line come from the thread metadata.
    """
    trigger_lower = trigger.lower()
    triggered: List[TriggeredThread] = []

    for thread in pr.threads:
        if thread.is_resolved or thread.is_outdated:
            continue
        if thread.id in processed_ids:
            continue

        # Search all comments for trigger
        instruction: Optional[str] = None
        author: str = "unknown"
        author_association: str = "NONE"
        diff_hunk: str = ""
        comment_node_id: str = ""

        for comment in thread.comments:
            if trigger_lower in comment.body.lower():
                # Strip the trigger tag from the instruction
                raw = re.sub(re.escape(trigger), "", comment.body, flags=re.IGNORECASE).strip()
                instruction = raw
                author = comment.author
                author_association = comment.author_association
                comment_node_id = comment.id
                diff_hunk = comment.diff_hunk or (thread.comments[0].diff_hunk if thread.comments else "")
                break

        if instruction is not None:
            triggered.append(
                TriggeredThread(
                    thread_id=thread.id,
                    pr_number=pr.number,
                    pr_branch=pr.head_ref,
                    path=thread.path,
                    line=thread.line,
                    instruction=instruction,
                    diff_hunk=diff_hunk,
                    author=author,
                    comment_node_id=comment_node_id,
                    author_association=author_association,
                )
            )

    return triggered
