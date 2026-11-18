#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# seed-demo-data.sh — Idempotent demo data seeding via API Gateway
#
# Usage: ./scripts/seed-demo-data.sh [GATEWAY_URL]
#        Default GATEWAY_URL = http://localhost:8080
#
# Requires: curl, jq
# Idempotent: searches by business identifier before creating.
###############################################################################

GATEWAY="${1:-http://localhost:8080}"
TOKEN=""

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[0;34m%s\033[0m\n' "$*"; }

die() { red "FATAL: $*"; exit 1; }

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
auth_header() {
  if [ -n "$TOKEN" ]; then
    echo "Authorization: Bearer $TOKEN"
  else
    echo "X-No-Auth: true"
  fi
}

api_post() {
  local path="$1" body="$2"
  local status response
  response=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY$path" \
    -H "Content-Type: application/json" \
    -H "$(auth_header)" \
    -d "$body")
  status=$(echo "$response" | tail -1)
  body_out=$(echo "$response" | sed '$d')

  if [[ "$status" -ge 200 && "$status" -lt 300 ]]; then
    echo "$body_out"
    return 0
  elif [[ "$status" == "409" || "$status" == "400" ]]; then
    echo "$body_out"
    return 1
  else
    red "POST $path → HTTP $status"
    echo "$body_out" >&2
    return 1
  fi
}

api_get() {
  local path="$1"
  curl -sf "$GATEWAY$path" -H "$(auth_header)" -H "Content-Type: application/json"
}

# ---------------------------------------------------------------------------
# 1. Auth — login or create admin
# ---------------------------------------------------------------------------
seed_admin() {
  blue "=== Auth: logging in as admin ==="

  local login_response
  if login_response=$(api_post "/api/auth/login" '{"username":"admin","password":"admin123"}'); then
    TOKEN=$(echo "$login_response" | jq -r '.accessToken // .token // empty')
    if [ -n "$TOKEN" ]; then
      green "  Logged in as admin"
      return
    fi
  fi

  blue "  Admin login failed, attempting to create admin user..."
  local create_response
  if create_response=$(api_post "/api/auth/users" '{
    "username": "admin",
    "email": "admin@hotel.local",
    "password": "admin123",
    "firstName": "Admin",
    "lastName": "System",
    "role": "ADMIN"
  }'); then
    green "  Admin user created"
  else
    blue "  Admin user may already exist, retrying login..."
  fi

  login_response=$(api_post "/api/auth/login" '{"username":"admin","password":"admin123"}') \
    || die "Cannot login as admin after creation attempt"
  TOKEN=$(echo "$login_response" | jq -r '.accessToken // .token // empty')
  [ -n "$TOKEN" ] || die "Login succeeded but no token returned"
  green "  Logged in as admin (token obtained)"
}

# ---------------------------------------------------------------------------
# 2. Rooms
# ---------------------------------------------------------------------------
seed_rooms() {
  blue "=== Rooms ==="
  local existing
  existing=$(api_get "/api/rooms?active=true" 2>/dev/null || echo "[]")

  local -a numbers=("101" "102" "201" "202" "301")
  local -a floors=(1 1 2 2 3)
  local -a types=("SINGLE" "DOUBLE" "TWIN" "SUITE" "FAMILY")
  local -a prices=("85.00" "120.00" "110.00" "250.00" "180.00")
  local -a capacities=(1 2 2 2 4)

  for i in "${!numbers[@]}"; do
    local num="${numbers[$i]}"
    # Check if room already exists by number
    local found
    if echo "$existing" | jq -e 'type == "array"' >/dev/null 2>&1; then
      found=$(echo "$existing" | jq -r --arg n "$num" '.[] | select(.number == $n) | .id // empty')
    else
      found=$(echo "$existing" | jq -r --arg n "$num" '.content[]? | select(.number == $n) | .id // empty')
    fi

    if [ -n "$found" ]; then
      green "  Room $num already exists (id=$found)"
    else
      local result
      if result=$(api_post "/api/rooms" "{
        \"number\": \"$num\",
        \"floor\": ${floors[$i]},
        \"type\": \"${types[$i]}\",
        \"pricePerNight\": ${prices[$i]},
        \"capacity\": ${capacities[$i]},
        \"status\": \"AVAILABLE\",
        \"description\": \"Chambre $num — ${types[$i]}\"
      }"); then
        local rid
        rid=$(echo "$result" | jq -r '.id')
        green "  Created room $num (id=$rid)"
      else
        red "  Failed to create room $num (may already exist)"
      fi
    fi
  done
}

# ---------------------------------------------------------------------------
# 3. Clients
# ---------------------------------------------------------------------------
seed_clients() {
  blue "=== Clients ==="
  local existing
  existing=$(api_get "/api/clients" 2>/dev/null || echo "[]")

  local -A clients
  clients[AA123456]='{"firstName":"Youssef","lastName":"Amrani","email":"youssef.amrani@mail.com","phone":"+212600000001","cin":"AA123456","nationality":"MA","address":"Casablanca","birthDate":"1990-05-15"}'
  clients[BB789012]='{"firstName":"Sofia","lastName":"Bennani","email":"sofia.bennani@mail.com","phone":"+212600000002","cin":"BB789012","nationality":"MA","address":"Rabat","birthDate":"1988-11-22"}'
  clients[CC345678]='{"firstName":"Karim","lastName":"El Fassi","email":"karim.elfassi@mail.com","phone":"+212600000003","cin":"CC345678","nationality":"MA","address":"Marrakech","birthDate":"1995-03-08"}'

  for cin in "${!clients[@]}"; do
    local found
    if echo "$existing" | jq -e 'type == "array"' >/dev/null 2>&1; then
      found=$(echo "$existing" | jq -r --arg c "$cin" '.[] | select(.cin == $c) | .id // empty')
    else
      found=$(echo "$existing" | jq -r --arg c "$cin" '.content[]? | select(.cin == $c) | .id // empty')
    fi

    if [ -n "$found" ]; then
      green "  Client CIN=$cin already exists (id=$found)"
    else
      local result
      if result=$(api_post "/api/clients" "${clients[$cin]}"); then
        local cid
        cid=$(echo "$result" | jq -r '.id')
        green "  Created client CIN=$cin (id=$cid)"
      else
        red "  Failed to create client CIN=$cin (may already exist)"
      fi
    fi
  done
}

# ---------------------------------------------------------------------------
# 4. Employees (Staff)
# ---------------------------------------------------------------------------
seed_employees() {
  blue "=== Employees ==="
  local existing
  existing=$(api_get "/api/employees?size=100" 2>/dev/null || echo '{"content":[]}')

  local -A employees
  employees[EE100001]='{"firstName":"Fatima","lastName":"Zohra","email":"fatima.zohra@hotel.local","phone":"+212600000010","cin":"EE100001","department":"HOUSEKEEPING"}'
  employees[EE100002]='{"firstName":"Hassan","lastName":"Moukrim","email":"hassan.moukrim@hotel.local","phone":"+212600000011","cin":"EE100002","department":"HOUSEKEEPING"}'
  employees[EE100003]='{"firstName":"Nadia","lastName":"Oukacha","email":"nadia.oukacha@hotel.local","phone":"+212600000012","cin":"EE100003","department":"RECEPTION"}'

  for cin in "${!employees[@]}"; do
    local found
    found=$(echo "$existing" | jq -r --arg c "$cin" '.content[]? | select(.cin == $c) | .id // empty' 2>/dev/null)

    if [ -n "$found" ]; then
      green "  Employee CIN=$cin already exists (id=$found)"
    else
      local result
      if result=$(api_post "/api/employees" "${employees[$cin]}"); then
        local eid
        eid=$(echo "$result" | jq -r '.id')
        green "  Created employee CIN=$cin (id=$eid)"
      else
        red "  Failed to create employee CIN=$cin (may already exist)"
      fi
    fi
  done
}

# ---------------------------------------------------------------------------
# 5. Reservations
# ---------------------------------------------------------------------------
seed_reservations() {
  blue "=== Reservations ==="

  # Resolve IDs by business identifiers
  local rooms clients
  rooms=$(api_get "/api/rooms?active=true" 2>/dev/null || echo "[]")
  clients=$(api_get "/api/clients" 2>/dev/null || echo "[]")

  local room101_id client_aa_id
  if echo "$rooms" | jq -e 'type == "array"' >/dev/null 2>&1; then
    room101_id=$(echo "$rooms" | jq -r '.[] | select(.number == "101") | .id')
  else
    room101_id=$(echo "$rooms" | jq -r '.content[]? | select(.number == "101") | .id')
  fi
  if echo "$clients" | jq -e 'type == "array"' >/dev/null 2>&1; then
    client_aa_id=$(echo "$clients" | jq -r '.[] | select(.cin == "AA123456") | .id')
  else
    client_aa_id=$(echo "$clients" | jq -r '.content[]? | select(.cin == "AA123456") | .id')
  fi

  if [ -z "$room101_id" ] || [ -z "$client_aa_id" ]; then
    red "  Cannot seed reservations: room 101 or client AA123456 not found"
    return
  fi

  # Check existing reservations for this room
  local existing_res
  existing_res=$(api_get "/api/reservations?roomId=$room101_id&clientId=$client_aa_id" 2>/dev/null || echo "[]")

  local already
  if echo "$existing_res" | jq -e 'type == "array"' >/dev/null 2>&1; then
    already=$(echo "$existing_res" | jq -r '.[0].id // empty')
  else
    already=$(echo "$existing_res" | jq -r '.content[0]?.id // empty' 2>/dev/null || echo "")
  fi

  if [ -n "$already" ]; then
    green "  Reservation for room 101 / client AA123456 already exists (id=$already)"
  else
    local checkin checkout
    checkin=$(date -d "+7 days" +%Y-%m-%d 2>/dev/null || date -v+7d +%Y-%m-%d 2>/dev/null || echo "2026-07-10")
    checkout=$(date -d "+10 days" +%Y-%m-%d 2>/dev/null || date -v+10d +%Y-%m-%d 2>/dev/null || echo "2026-07-13")

    local result
    if result=$(api_post "/api/reservations" "{
      \"roomId\": $room101_id,
      \"clientId\": $client_aa_id,
      \"checkInDate\": \"$checkin\",
      \"checkOutDate\": \"$checkout\",
      \"notes\": \"Seed demo reservation\"
    }"); then
      local resid
      resid=$(echo "$result" | jq -r '.id')
      green "  Created reservation room=101 client=AA123456 (id=$resid)"
    else
      red "  Failed to create reservation (may already exist or overlap)"
    fi
  fi
}

# ---------------------------------------------------------------------------
# 6. Housekeeping tasks
# ---------------------------------------------------------------------------
seed_housekeeping() {
  blue "=== Housekeeping Tasks ==="

  local rooms employees
  rooms=$(api_get "/api/rooms?active=true" 2>/dev/null || echo "[]")
  employees=$(api_get "/api/employees?department=HOUSEKEEPING&active=true&size=100" 2>/dev/null || echo '{"content":[]}')

  local room201_id agent_id
  if echo "$rooms" | jq -e 'type == "array"' >/dev/null 2>&1; then
    room201_id=$(echo "$rooms" | jq -r '.[] | select(.number == "201") | .id')
  else
    room201_id=$(echo "$rooms" | jq -r '.content[]? | select(.number == "201") | .id')
  fi
  agent_id=$(echo "$employees" | jq -r '.content[0]?.id // empty' 2>/dev/null)

  if [ -z "$room201_id" ]; then
    red "  Cannot seed housekeeping: room 201 not found"
    return
  fi

  # Check existing tasks for this room today
  local today
  today=$(date +%Y-%m-%d 2>/dev/null || echo "2026-06-27")
  local existing_tasks
  existing_tasks=$(api_get "/api/housekeeping-tasks?roomId=$room201_id&scheduledDate=$today&size=10" 2>/dev/null || echo '{"content":[]}')

  local task_exists
  task_exists=$(echo "$existing_tasks" | jq -r '.content[0]?.id // empty' 2>/dev/null)

  if [ -n "$task_exists" ]; then
    green "  Housekeeping task for room 201 today already exists (id=$task_exists)"
  else
    local body="{
      \"roomId\": $room201_id,
      \"type\": \"DAILY_CLEANING\",
      \"priority\": \"NORMAL\",
      \"scheduledDate\": \"$today\",
      \"notes\": \"Seed demo housekeeping task\""

    if [ -n "$agent_id" ]; then
      body="$body, \"assignedAgentId\": $agent_id"
    fi
    body="$body}"

    local result
    if result=$(api_post "/api/housekeeping-tasks" "$body"); then
      local tid
      tid=$(echo "$result" | jq -r '.id')
      green "  Created housekeeping task for room 201 (id=$tid)"
    else
      red "  Failed to create housekeeping task"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  blue "Hotel Management System — Demo Data Seed"
  blue "Gateway: $GATEWAY"
  echo ""

  seed_admin
  echo ""
  seed_rooms
  echo ""
  seed_clients
  echo ""
  seed_employees
  echo ""
  seed_reservations
  echo ""
  seed_housekeeping

  echo ""
  green "=== Seed complete ==="
}

main
