"""Tests for diff_parser module."""

from pr_review.diff_parser import parse_diff, DiffLine, DiffHunk, ChangedFile


# --- Helpers ---


def _simple_diff(filename: str = "backend/src/main.rs", lines: str = "") -> str:
    """Build a minimal unified diff for one file."""
    return (
        f"diff --git a/{filename} b/{filename}\n"
        f"--- a/{filename}\n"
        f"+++ b/{filename}\n"
        f"@@ -1,3 +1,4 @@\n"
        f"{lines}"
    )


# --- DiffLine ---


class TestDiffLine:
    def test_is_changed_added(self):
        line = DiffLine(
            line_number=1,
            content="x",
            is_added=True,
            is_removed=False,
            is_context=False,
        )
        assert line.is_changed

    def test_is_changed_removed(self):
        line = DiffLine(
            line_number=0,
            content="x",
            is_added=False,
            is_removed=True,
            is_context=False,
        )
        assert line.is_changed

    def test_is_changed_context(self):
        line = DiffLine(
            line_number=1,
            content="x",
            is_added=False,
            is_removed=False,
            is_context=True,
        )
        assert not line.is_changed


# --- ChangedFile properties ---


class TestChangedFileProperties:
    def test_extension(self):
        cf = ChangedFile(
            path="backend/src/main.rs",
            old_path=None,
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            is_binary=False,
        )
        assert cf.extension == ".rs"

    def test_filename(self):
        cf = ChangedFile(
            path="backend/src/connectors/stripe.rs",
            old_path=None,
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            is_binary=False,
        )
        assert cf.filename == "stripe.rs"

    def test_is_rust_file(self):
        cf = ChangedFile(
            path="foo.rs",
            old_path=None,
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            is_binary=False,
        )
        assert cf.is_rust_file
        cf2 = ChangedFile(
            path="foo.toml",
            old_path=None,
            is_new=False,
            is_deleted=False,
            is_renamed=False,
            is_binary=False,
        )
        assert not cf2.is_rust_file


# --- parse_diff ---


class TestParseDiff:
    def test_empty_input(self):
        assert parse_diff("") == []

    def test_single_file_addition(self):
        diff = (
            "diff --git a/src/lib.rs b/src/lib.rs\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/src/lib.rs\n"
            "@@ -0,0 +1,3 @@\n"
            "+use std::io;\n"
            "+\n"
            "+fn main() {}\n"
        )
        files = parse_diff(diff)
        assert len(files) == 1
        f = files[0]
        assert f.path == "src/lib.rs"
        assert f.is_new
        assert not f.is_deleted
        assert len(f.hunks) == 1
        assert len(f.added_lines) == 3

    def test_single_file_deletion(self):
        diff = (
            "diff --git a/src/old.rs b/src/old.rs\n"
            "deleted file mode 100644\n"
            "--- a/src/old.rs\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-fn old() {}\n"
            "-fn stale() {}\n"
        )
        files = parse_diff(diff)
        assert len(files) == 1
        f = files[0]
        assert f.is_deleted
        assert not f.is_new
        assert len(f.removed_lines) == 2
        assert len(f.added_lines) == 0

    def test_modification_with_context(self):
        diff = (
            "diff --git a/src/lib.rs b/src/lib.rs\n"
            "--- a/src/lib.rs\n"
            "+++ b/src/lib.rs\n"
            "@@ -5,6 +5,7 @@ fn helper() {\n"
            "     let x = 1;\n"
            "-    let y = 2;\n"
            "+    let y = 3;\n"
            "+    let z = 4;\n"
            '     println!("{}", x);\n'
        )
        files = parse_diff(diff)
        assert len(files) == 1
        hunk = files[0].hunks[0]
        assert hunk.old_start == 5
        assert hunk.new_start == 5
        added = hunk.added_lines
        removed = hunk.removed_lines
        assert len(added) == 2
        assert len(removed) == 1
        # Removed lines have line_number == 0
        assert removed[0].line_number == 0
        # Added lines have the new-file line number
        assert added[0].line_number == 6  # (new_start=5, context=1 line, added at 6)

    def test_multiple_files(self):
        diff = (
            "diff --git a/a.rs b/a.rs\n"
            "--- a/a.rs\n"
            "+++ b/a.rs\n"
            "@@ -1,1 +1,2 @@\n"
            " existing\n"
            "+new_line\n"
            "diff --git a/b.rs b/b.rs\n"
            "--- a/b.rs\n"
            "+++ b/b.rs\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        files = parse_diff(diff)
        assert len(files) == 2
        assert files[0].path == "a.rs"
        assert files[1].path == "b.rs"

    def test_renamed_file(self):
        diff = (
            "diff --git a/old_name.rs b/new_name.rs\n"
            "similarity index 95%\n"
            "rename from old_name.rs\n"
            "rename to new_name.rs\n"
            "--- a/old_name.rs\n"
            "+++ b/new_name.rs\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        files = parse_diff(diff)
        assert len(files) == 1
        f = files[0]
        assert f.is_renamed
        assert f.old_path == "old_name.rs"
        assert f.path == "new_name.rs"

    def test_binary_file(self):
        diff = (
            "diff --git a/image.png b/image.png\n"
            "Binary files a/image.png and b/image.png differ\n"
        )
        files = parse_diff(diff)
        assert len(files) == 1
        assert files[0].is_binary

    def test_multiple_hunks(self):
        diff = (
            "diff --git a/src/lib.rs b/src/lib.rs\n"
            "--- a/src/lib.rs\n"
            "+++ b/src/lib.rs\n"
            "@@ -1,3 +1,3 @@\n"
            " fn a() {\n"
            "-    old_a();\n"
            "+    new_a();\n"
            " }\n"
            "@@ -20,3 +20,3 @@\n"
            " fn b() {\n"
            "-    old_b();\n"
            "+    new_b();\n"
            " }\n"
        )
        files = parse_diff(diff)
        assert len(files) == 1
        assert len(files[0].hunks) == 2
        assert files[0].hunks[0].new_start == 1
        assert files[0].hunks[1].new_start == 20

    def test_hunk_header_without_count(self):
        """Hunk headers like @@ -1 +1 @@ (omitting counts) should default count to 1."""
        diff = (
            "diff --git a/x.rs b/x.rs\n"
            "--- a/x.rs\n"
            "+++ b/x.rs\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        files = parse_diff(diff)
        hunk = files[0].hunks[0]
        assert hunk.old_count == 1
        assert hunk.new_count == 1

    def test_no_newline_at_eof_marker_skipped(self):
        diff = (
            "diff --git a/x.rs b/x.rs\n"
            "--- a/x.rs\n"
            "+++ b/x.rs\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "\\ No newline at end of file\n"
            "+new\n"
        )
        files = parse_diff(diff)
        lines = files[0].hunks[0].lines
        # The backslash line should be skipped
        assert all(not l.content.startswith("\\") for l in lines)

    def test_all_changed_lines(self):
        diff = _simple_diff(lines=" ctx\n+added\n-removed\n")
        files = parse_diff(diff)
        changed = files[0].all_changed_lines
        assert len(changed) == 2  # 1 added + 1 removed

    def test_added_line_numbers_sequential(self):
        diff = (
            "diff --git a/x.rs b/x.rs\n"
            "--- a/x.rs\n"
            "+++ b/x.rs\n"
            "@@ -1,2 +1,4 @@\n"
            " existing\n"
            "+line_a\n"
            "+line_b\n"
            " another_existing\n"
        )
        files = parse_diff(diff)
        added = files[0].added_lines
        assert [l.line_number for l in added] == [2, 3]
