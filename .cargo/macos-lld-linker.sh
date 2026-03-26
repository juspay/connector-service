#!/usr/bin/env bash
# macOS linker wrapper — uses ld64.lld (LLVM) when available for faster
# linking of large dylibs, otherwise falls back to the system linker.
#
# Install lld for the speed benefit: brew install lld

LLD_PATH=""
if [ -f /opt/homebrew/opt/lld/bin/ld64.lld ]; then
  LLD_PATH="/opt/homebrew/opt/lld/bin/ld64.lld"
elif command -v ld64.lld >/dev/null 2>&1; then
  LLD_PATH="$(command -v ld64.lld)"
fi

# ld64.lld does not inherit the system linker's default library search paths,
# so Homebrew-installed native libs (e.g. libpq) are not found without these.
BREW_LIBS=""
[ -d /opt/homebrew/lib ] && BREW_LIBS="$BREW_LIBS -L/opt/homebrew/lib"
[ -d /usr/local/lib ]    && BREW_LIBS="$BREW_LIBS -L/usr/local/lib"

if [ -n "$LLD_PATH" ]; then
  exec clang -fuse-ld="$LLD_PATH" $BREW_LIBS "$@"
else
  exec clang "$@"
fi
