#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$(uname -s)" != Linux ]; then
    echo "usage: install-rage.sh BIN_DIRECTORY (Linux only)" >&2
    exit 2
fi
rage_bin_directory=$1
rage_revision=0323ec863466ce8d242b27670ea6707d33f7d60c
case "$(uname -m)" in
    x86_64) rage_arch=x86_64; rage_sha256=90dc2da6b8530361079aaaf86898105e8fc6e1093b7954fbb9895e4b65dccb69 ;;
    aarch64) rage_arch=aarch64; rage_sha256=a536000d323bf6d5072f16abef66b234e2948cd639c3388a23472daef44a7f7d ;;
    *) echo "unsupported rage test architecture" >&2; exit 2 ;;
esac
rage_repository=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
mkdir -p "$rage_repository/.work/tmp" "$rage_bin_directory"
rage_scratch=$(mktemp -d "$rage_repository/.work/tmp/rage-XXXXXX")
trap 'rm -rf "$rage_scratch"' EXIT HUP INT TERM
rage_asset="rage-$rage_arch-unknown-linux-musl-static"
wget -q -T 60 -O "$rage_scratch/rage.tar.xz" \
    "https://github.com/laputa-systems/rage/releases/download/release-$rage_revision/$rage_asset.tar.xz"
echo "$rage_sha256  $rage_scratch/rage.tar.xz" | sha256sum -c -
tar xf "$rage_scratch/rage.tar.xz" -C "$rage_scratch"
install -m 755 "$rage_scratch/$rage_asset" "$rage_bin_directory/rage"
"$rage_bin_directory/rage" --version
