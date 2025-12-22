#!/bin/bash
set -euo pipefail

# Configuration
EMULATOR_URL="http://gcs-emulator:9000"
BUCKET="content"
POSTS_DIR="frontend/content/posts"

log() {
    echo "[upload] $1"
}

log "Ensuring bucket exists..."
curl -s -X POST "$EMULATOR_URL/storage/v1/b?project=test" \
     -H "Content-Type: application/json" \
     -d "{\"name\":\"$BUCKET\"}" > /dev/null || true

log "Starting content upload..."

find "$POSTS_DIR" -name "*.md" | while read -r md; do
  SLUG=$(basename "$md" .md)
  HTML="frontend/public/posts/$SLUG/index.html"
  OBJECT_PATH="posts/$SLUG/index.html"
  # URL encode the slash for the API call
  ENCODED_PATH="posts%2F$SLUG%2Findex.html"

  if [[ ! -f "$HTML" ]]; then
    log "Warning: HTML file not found for $SLUG, skipping..."
    continue
  fi

  PLANS=$(awk '
    BEGIN { in_fm=0; found="" }
    /^\+\+\+/ { in_fm = !in_fm; next }
    in_fm && $0 ~ /^categories[[:space:]]*=/ {
      gsub(/[\[\]"'\'' ]/, "", $0)
      split($0, parts, "=")
      found = parts[2]
    }
    END { print found }' "$md")

  if [[ -z "$PLANS" ]]; then
    log "Uploading public: $SLUG"
    curl -s -X POST "$EMULATOR_URL/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$ENCODED_PATH" \
         --data-binary @"$HTML" > /dev/null
  else
    log "Uploading gated: $SLUG (plans: $PLANS)"
    # Upload with metadata via multipart request
    curl -s -X POST "$EMULATOR_URL/upload/storage/v1/b/$BUCKET/o?uploadType=multipart" \
         -H "Content-Type: multipart/related; boundary=foo_bar_baz" \
         --data-binary "--foo_bar_baz
Content-Type: application/json; charset=UTF-8

{
  \"name\": \"$OBJECT_PATH\",
  \"metadata\": {
    \"required-plans\": \"$PLANS\"
  }
}

--foo_bar_baz
Content-Type: text/html

$(cat "$HTML")
--foo_bar_baz--" > /dev/null
  fi
done

log "Upload complete."
