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

if [ -n "$LLD_PATH" ]; then
  exec clang -fuse-ld="$LLD_PATH" "$@"
else
  exec clang "$@"
fi
