#!/bin/sh
ZIG_CMD="${ZIG_BIN:-$(command -v zig 2>/dev/null || echo /opt/homebrew/bin/zig)}"
exec "$ZIG_CMD" ar "$@"
