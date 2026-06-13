#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
PROFILE_ARG=()
SOUNDER_PROFILE_ARG=()
CREATED_BUCKET=0
WORK_DIR=""
PREFIX=""

if [[ -n "${AWS_PROFILE:-}" ]]; then
  PROFILE_ARG=(--profile "$AWS_PROFILE")
  SOUNDER_PROFILE_ARG=(--profile "$AWS_PROFILE")
fi

aws_cmd() {
  if [[ "${SOUNDER_AWS_DIRECT:-0}" == "1" ]]; then
    if [[ -n "${AWS_PROFILE:-}" ]]; then
      env \
        -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        -u http_proxy -u https_proxy -u all_proxy \
        aws --profile "$AWS_PROFILE" "$@"
    else
      env \
        -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        -u http_proxy -u https_proxy -u all_proxy \
        aws "$@"
    fi
  else
    if [[ -n "${AWS_PROFILE:-}" ]]; then
      aws --profile "$AWS_PROFILE" "$@"
    else
      aws "$@"
    fi
  fi
}

sounder_cmd() {
  if [[ "${SOUNDER_AWS_DIRECT:-0}" == "1" ]]; then
    env \
      -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
      -u http_proxy -u https_proxy -u all_proxy \
      "$SOUNDER" "$@"
  else
    "$SOUNDER" "$@"
  fi
}

cleanup() {
  local status=$?
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
  if [[ "${SOUNDER_S3_KEEP:-0}" != "1" && -n "${SOUNDER_S3_BUCKET:-}" && -n "$PREFIX" ]]; then
    aws_cmd s3 rm "s3://${SOUNDER_S3_BUCKET}/${PREFIX}" --recursive >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_BUCKET" == "1" && -n "${SOUNDER_S3_BUCKET:-}" ]]; then
    aws_cmd s3 rb "s3://${SOUNDER_S3_BUCKET}" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need aws
need cargo

ACCOUNT_ID="$(aws_cmd sts get-caller-identity --query Account --output text)"
if [[ -n "${SOUNDER_AWS_ACCOUNT_ID:-}" && "$ACCOUNT_ID" != "$SOUNDER_AWS_ACCOUNT_ID" ]]; then
  echo "AWS account mismatch: expected ${SOUNDER_AWS_ACCOUNT_ID}, got ${ACCOUNT_ID}" >&2
  exit 5
fi

if [[ -n "${AWS_PROFILE:-}" ]]; then
  if CREDS_EXPORT="$(aws_cmd configure export-credentials --format env 2>/dev/null)"; then
    eval "$CREDS_EXPORT"
    SOUNDER_PROFILE_ARG=()
  fi
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sounder-s3-it.XXXXXX")"
cargo run --quiet --example make_s3_fixtures -- "$WORK_DIR/fixtures" >/dev/null
cargo build --quiet

if [[ -z "${SOUNDER_S3_BUCKET:-}" ]]; then
  SOUNDER_S3_BUCKET="sounder-it-${ACCOUNT_ID}-${REGION}-$(date +%s)-$RANDOM"
  if [[ "$REGION" == "us-east-1" ]]; then
    aws_cmd s3api create-bucket --bucket "$SOUNDER_S3_BUCKET" --region "$REGION" >/dev/null
  else
    aws_cmd s3api create-bucket \
      --bucket "$SOUNDER_S3_BUCKET" \
      --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi
  CREATED_BUCKET=1
fi

PREFIX="${SOUNDER_S3_PREFIX:-sounder-integration/$(date +%Y%m%dT%H%M%S)-$RANDOM/}"
PREFIX="${PREFIX#/}"
if [[ "$PREFIX" != */ ]]; then
  PREFIX="${PREFIX}/"
fi
aws_cmd s3 cp "$WORK_DIR/fixtures/" "s3://${SOUNDER_S3_BUCKET}/${PREFIX}" --recursive >/dev/null

SOUNDER="$ROOT_DIR/target/debug/sounder"
SOUNDER_ARGS=(--region "$REGION")
if [[ ${#SOUNDER_PROFILE_ARG[@]} -gt 0 ]]; then
  SOUNDER_ARGS+=("${SOUNDER_PROFILE_ARG[@]}")
fi
HEALTHY_URI="s3://${SOUNDER_S3_BUCKET}/${PREFIX}healthy.parquet"
DATASET_URI="s3://${SOUNDER_S3_BUCKET}/${PREFIX}"

sounder_cmd inspect "$HEALTHY_URI" --json "${SOUNDER_ARGS[@]}" \
  > "$WORK_DIR/inspect.json"
sounder_cmd inspect "$HEALTHY_URI" --head 2 --json "${SOUNDER_ARGS[@]}" \
  > "$WORK_DIR/inspect-head.json"
CHECK_EXIT=0
sounder_cmd check "$DATASET_URI" --json "${SOUNDER_ARGS[@]}" \
  --max-files 10 --s3-concurrency 4 > "$WORK_DIR/check.json" || CHECK_EXIT=$?

if [[ "$CHECK_EXIT" != "1" ]]; then
  echo "expected sounder check to exit 1 because fixtures contain schema drift/corrupt file; got $CHECK_EXIT" >&2
  cat "$WORK_DIR/check.json" >&2
  exit 1
fi

grep -q '"schema_version": "sounder.report.v1"' "$WORK_DIR/inspect.json"
grep -q '"data_pages_read": true' "$WORK_DIR/inspect-head.json"
grep -q '"returned_rows": 2' "$WORK_DIR/inspect-head.json"
grep -q '"type": "schema_drift"' "$WORK_DIR/check.json"
grep -q '"type": "unreadable_file"' "$WORK_DIR/check.json"

echo "S3 integration test passed"
echo "  bucket: s3://${SOUNDER_S3_BUCKET}"
echo "  prefix: s3://${SOUNDER_S3_BUCKET}/${PREFIX}"
if [[ "${SOUNDER_S3_KEEP:-0}" == "1" ]]; then
  echo "  cleanup: skipped because SOUNDER_S3_KEEP=1"
fi
