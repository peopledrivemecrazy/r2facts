#!/usr/bin/env bash
set -euo pipefail

readonly DIRECTORY_TYPE="application/vnd.r2facts.tar+gzip"

fail() {
  echo "::error title=r2facts::$*" >&2
  exit 1
}

uri_encode_path() {
  jq -rn --arg path "${1#/}" '$path | split("/") | map(@uri) | join("/")'
}

request_oidc_token() {
  local audience response
  audience=$(jq -rn --arg value "$R2FACTS_AUDIENCE" '$value | @uri')
  response=$(curl -fsS --retry 3 \
    --header @<(printf 'Authorization: bearer %s' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN") \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$audience") || fail "could not get a GitHub OIDC token"
  jq -r '.value // empty' <<<"$response"
}

worker() {
  curl --fail-with-body -sS --retry 3 --retry-connrefused \
    --header @<(printf 'Authorization: Bearer %s' "$TOKEN") "$@"
}

upload() {
  local file content_type
  if [[ -d "$R2FACTS_PATH" ]]; then
    file="$WORK_DIR/upload.tar.gz"
    tar -czf "$file" -C "$R2FACTS_PATH" .
    content_type=$DIRECTORY_TYPE
  elif [[ -f "$R2FACTS_PATH" ]]; then
    file=$R2FACTS_PATH
    content_type=application/octet-stream
  else
    fail "path not found: $R2FACTS_PATH"
  fi

  worker --upload-file "$file" --header "Content-Type: $content_type" "$OBJECT_URL" || fail "upload of $R2FACTS_KEY failed"
  echo
}

download() {
  local body headers content_type target
  body="$WORK_DIR/body"
  headers="$WORK_DIR/headers"

  if ! worker --dump-header "$headers" --output "$body" "$OBJECT_URL"; then
    cat "$body" >&2
    echo >&2
    fail "download of $R2FACTS_KEY failed"
  fi
  content_type=$(grep -i '^content-type:' "$headers" | tail -n 1 | cut -d: -f2- | tr -d ' \r')

  if [[ "$content_type" == "$DIRECTORY_TYPE" ]]; then
    mkdir -p "$R2FACTS_PATH"
    tar -xzf "$body" -C "$R2FACTS_PATH"
    return
  fi

  target=$R2FACTS_PATH
  [[ -d "$target" ]] && target="$target/$(basename "$R2FACTS_KEY")"
  mkdir -p "$(dirname "$target")"
  mv "$body" "$target"
}

delete() {
  worker --request DELETE "$OBJECT_URL" || fail "delete of $R2FACTS_KEY failed"
}

[[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]] ||
  fail "no OIDC token available; the job needs 'permissions: id-token: write'"
[[ -n "${R2FACTS_URL:-}" ]] || fail "url is required"
[[ -n "${R2FACTS_KEY:-}" ]] || fail "key is required"
case "${R2FACTS_MODE:-}" in
  upload | download) [[ -n "${R2FACTS_PATH:-}" ]] || fail "path is required for $R2FACTS_MODE" ;;
  delete) ;;
  *) fail "mode must be upload, download or delete" ;;
esac

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

TOKEN=$(request_oidc_token)
[[ -n "$TOKEN" ]] || fail "GitHub returned an empty OIDC token"
echo "::add-mask::$TOKEN"
OBJECT_URL="${R2FACTS_URL%/}/$(uri_encode_path "$R2FACTS_KEY")"

"$R2FACTS_MODE"
