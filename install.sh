#!/bin/sh
# Installs the latest guard binary into ~/.local/bin (or $GUARD_INSTALL_DIR).
set -eu

repo=defi0x1/agent-guard
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-gnu ;;
  *)
    echo "No prebuilt guard for $(uname -sm). Run: cargo install --git https://github.com/$repo" >&2
    exit 1
    ;;
esac

dir=${GUARD_INSTALL_DIR:-$HOME/.local/bin}
url=https://github.com/$repo/releases/latest/download/guard-$target.tar.gz
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$url" -o "$tmp/guard.tar.gz"
curl -fsSL "$url.sha256" -o "$tmp/guard.sha256"
want=$(cut -d' ' -f1 "$tmp/guard.sha256")
got=$( (sha256sum "$tmp/guard.tar.gz" 2>/dev/null || shasum -a 256 "$tmp/guard.tar.gz") | cut -d' ' -f1)
if [ "$want" != "$got" ]; then
  echo "Checksum mismatch for $url" >&2
  exit 1
fi

tar xzf "$tmp/guard.tar.gz" -C "$tmp"
mkdir -p "$dir"
# Write a new file and rename it over the old one. Overwriting a running binary in place makes
# macOS kill it, and every hook call would then fail closed.
install -m 755 "$tmp/guard-$target/guard" "$dir/.guard.new"
mv -f "$dir/.guard.new" "$dir/guard"
echo "Installed $dir/guard"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH first." ;;
esac
echo "Next: guard install && guard selftest"
