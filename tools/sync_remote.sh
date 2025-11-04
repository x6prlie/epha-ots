#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

PORT=8022
REMOTE_ROOT="~/src/epha-ots"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [-p port] [-d remote_path] user@host

Copies the project sources to the remote host via scp.

Options:
  -p port         SSH port to use (default: 8022)
  -d remote_path  Remote project directory (default: ~/src/epha-ots)
  -h              Show this help and exit
USAGE
  exit 1
}

while getopts ":p:d:h" opt; do
  case "$opt" in
    p) PORT=$OPTARG ;;
    d) REMOTE_ROOT=$OPTARG ;;
    h) usage ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage ;;
  esac
done
shift $((OPTIND - 1))

if [ $# -ne 1 ]; then
  usage
fi

REMOTE=$1

if ! command -v scp >/dev/null 2>&1; then
  echo "Error: scp is not available in PATH." >&2
  exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "Error: ssh is not available in PATH." >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

ssh -p "$PORT" "$REMOTE" "mkdir -p $REMOTE_ROOT $REMOTE_ROOT/tools $REMOTE_ROOT/assets"

copy_files() {
  local mode=$1
  shift
  local destination=$1
  shift
  if [ $# -eq 0 ]; then
    return
  fi

  local scp_args=(-P "$PORT")
  if [ "$mode" = "recursive" ]; then
    scp_args+=(-r)
  fi

  echo "Copying $# item(s) to $REMOTE:$destination"
  scp "${scp_args[@]}" "$@" "$REMOTE:$destination"
}

copy_files normal "$REMOTE_ROOT" "$PROJECT_ROOT"/*.c "$PROJECT_ROOT"/*.h
copy_files recursive "$REMOTE_ROOT/tools/" "$PROJECT_ROOT"/tools/*
copy_files recursive "$REMOTE_ROOT/assets/" "$PROJECT_ROOT"/assets/*

echo "Copy completed."
