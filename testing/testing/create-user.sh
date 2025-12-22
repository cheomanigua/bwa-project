#!/bin/bash

# Usage: ./create_user.sh [username] [plan]
# Example: ./create_user.sh joe elite -> joe@test.com with elite plan
# Example: ./create_user.sh pro       -> pro@test.com with pro plan

if [ -z "$1" ]; then
    echo "Usage: ./create_user.sh [username] [plan]"
    echo "Example: ./create_user.sh joe elite"
    exit 1
fi

# Logic to handle 1 or 2 arguments
if [ -z "$2" ]; then
    # Only one argument provided: use it as both name and plan
    USER_NAME=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    PLAN=$USER_NAME
else
    # Two arguments provided
    USER_NAME=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    PLAN=$(echo "$2" | tr '[:upper:]' '[:lower:]')
fi

EMAIL="${USER_NAME}@mail.com"
PASS="pepepepe"
PROJECT="my-test-project"

# Generate Next Renewal Date (Current time + 30 days)
RENEWAL_DATE=$(date -u -d "+30 days" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+30d +"%Y-%m-%dT%H:%M:%SZ")

echo "1. Creating Auth Account for $EMAIL ($PLAN plan)..."
RESPONSE=$(curl -s -X POST "http://localhost:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-key" \
     -H "Content-Type: application/json" \
     -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\",\"returnSecureToken\":true}")

FUID=$(echo "$RESPONSE" | grep -o '"localId":"[^"]*' | cut -d'"' -f4)

if [ -z "$FUID" ]; then
    echo "Error: Could not extract UID. Response: $RESPONSE"
    exit 1
fi

echo "Auth UID: $FUID"

# 2. Force Write to Firestore using Admin Bypass Header
echo "2. Writing $PLAN profile to Firestore..."
curl -s -X PATCH "http://localhost:8080/v1/projects/$PROJECT/databases/(default)/documents/users/$FUID?updateMask.fieldPaths=plan&updateMask.fieldPaths=email&updateMask.fieldPaths=next_renewal_date&allow_missing=true" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer owner" \
     -d "{
       \"fields\": {
         \"email\": { \"stringValue\": \"$EMAIL\" },
         \"plan\": { \"stringValue\": \"$PLAN\" },
         \"next_renewal_date\": { \"timestampValue\": \"$RENEWAL_DATE\" }
       }
     }"

echo -e "\n\n3. Verification for $EMAIL:"
curl -s "http://localhost:8080/v1/projects/$PROJECT/databases/(default)/documents/users/$FUID" \
     -H "Authorization: Bearer owner"
