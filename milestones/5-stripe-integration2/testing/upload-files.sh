podman run --rm --network testing_custom_app_network \
  -v "${PWD}:/app" \
  -w /app \
  google/cloud-sdk:slim \
  /bin/bash .././upload_posts.sh
