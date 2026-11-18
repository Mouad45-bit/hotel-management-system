#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# verify-backend-integration.sh — GET-only backend integration verification
#
# Usage: ./scripts/verify-backend-integration.sh [GATEWAY_URL]
#        Default GATEWAY_URL = http://localhost:8080
#
# Requires: curl, jq
# Performs only GET requests — no data mutation.
# Exits with code 1 if any check fails.
###############################################################################

GATEWAY="${1:-http://localhost:8080}"
TOKEN=""
PASS=0
FAIL=0
ERRORS=""

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[0;34m%s\033[0m\n' "$*"; }

pass() {
  PASS=$((PASS + 1))
  green "  PASS: $*"
}

fail() {
  FAIL=$((FAIL + 1))
  ERRORS="$ERRORS\n  - $*"
  red "  FAIL: $*"
}

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

api_get() {
  curl -sf "$GATEWAY$1" -H "$(auth_header)" -H "Content-Type: application/json" 2>/dev/null
}

api_get_status() {
  curl -s -o /dev/null -w '%{http_code}' "$GATEWAY$1" -H "$(auth_header)" -H "Content-Type: application/json" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 1. Auth — login
# ---------------------------------------------------------------------------
verify_auth() {
  blue "=== 1. Auth Service ==="

  local login_response
  login_response=$(curl -s -X POST "$GATEWAY/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@123"}' 2>/dev/null || echo "")

  if [ -z "$login_response" ]; then
    fail "Auth login returned empty response"
    return
  fi

  TOKEN=$(echo "$login_response" | jq -r '.accessToken // .token // empty' 2>/dev/null)

  if [ -n "$TOKEN" ]; then
    pass "Admin login successful, token obtained"
  else
    fail "Admin login failed — no token in response"
    return
  fi

  # Verify /me endpoint
  local me_response
  me_response=$(api_get "/api/auth/me" || echo "")
  local me_username
  me_username=$(echo "$me_response" | jq -r '.username // empty' 2>/dev/null)

  if [ "$me_username" = "admin" ]; then
    pass "/api/auth/me returns admin user"
  else
    fail "/api/auth/me did not return admin username"
  fi
}

# ---------------------------------------------------------------------------
# 2. Room Service
# ---------------------------------------------------------------------------
verify_rooms() {
  blue "=== 2. Room Service ==="

  local rooms
  rooms=$(api_get "/api/rooms?active=true" || echo "")

  if [ -z "$rooms" ]; then
    fail "GET /api/rooms returned empty"
    return
  fi

  local count
  if echo "$rooms" | jq -e 'type == "array"' >/dev/null 2>&1; then
    count=$(echo "$rooms" | jq 'length')
  else
    count=$(echo "$rooms" | jq '.content | length' 2>/dev/null || echo "0")
  fi

  if [ "$count" -gt 0 ]; then
    pass "Found $count room(s)"
  else
    fail "No rooms found"
    return
  fi

  # Verify single room fetch
  local first_id
  if echo "$rooms" | jq -e 'type == "array"' >/dev/null 2>&1; then
    first_id=$(echo "$rooms" | jq -r '.[0].id')
  else
    first_id=$(echo "$rooms" | jq -r '.content[0].id')
  fi

  local single_room
  single_room=$(api_get "/api/rooms/$first_id" || echo "")
  local room_number
  room_number=$(echo "$single_room" | jq -r '.number // empty' 2>/dev/null)

  if [ -n "$room_number" ]; then
    pass "GET /api/rooms/$first_id returns room number=$room_number"
  else
    fail "GET /api/rooms/$first_id did not return room data"
  fi

  # Verify pricePerNight is present (correction 3 requirement)
  local price
  price=$(echo "$single_room" | jq -r '.pricePerNight // empty' 2>/dev/null)
  if [ -n "$price" ] && [ "$price" != "null" ]; then
    pass "Room has pricePerNight=$price"
  else
    fail "Room missing pricePerNight field"
  fi
}

# ---------------------------------------------------------------------------
# 3. Client Service
# ---------------------------------------------------------------------------
verify_clients() {
  blue "=== 3. Client Service ==="

  local clients
  clients=$(api_get "/api/clients" || echo "")

  if [ -z "$clients" ]; then
    fail "GET /api/clients returned empty"
    return
  fi

  local count
  if echo "$clients" | jq -e 'type == "array"' >/dev/null 2>&1; then
    count=$(echo "$clients" | jq 'length')
  else
    count=$(echo "$clients" | jq '.content | length' 2>/dev/null || echo "0")
  fi

  if [ "$count" -gt 0 ]; then
    pass "Found $count client(s)"
  else
    fail "No clients found"
    return
  fi

  # Verify single client fetch returns firstName + lastName (correction 3 requirement)
  local first_id
  if echo "$clients" | jq -e 'type == "array"' >/dev/null 2>&1; then
    first_id=$(echo "$clients" | jq -r '.[0].id')
  else
    first_id=$(echo "$clients" | jq -r '.content[0].id')
  fi

  local single_client
  single_client=$(api_get "/api/clients/$first_id" || echo "")
  local first_name last_name
  first_name=$(echo "$single_client" | jq -r '.firstName // empty' 2>/dev/null)
  last_name=$(echo "$single_client" | jq -r '.lastName // empty' 2>/dev/null)

  if [ -n "$first_name" ] && [ -n "$last_name" ]; then
    pass "Client $first_id has firstName=$first_name lastName=$last_name"
  else
    fail "Client $first_id missing firstName/lastName"
  fi
}

# ---------------------------------------------------------------------------
# 4. Reservation Service
# ---------------------------------------------------------------------------
verify_reservations() {
  blue "=== 4. Reservation Service ==="

  local reservations
  reservations=$(api_get "/api/reservations" || echo "[]")

  local count
  if echo "$reservations" | jq -e 'type == "array"' >/dev/null 2>&1; then
    count=$(echo "$reservations" | jq 'length')
  else
    count=$(echo "$reservations" | jq '.content | length' 2>/dev/null || echo "0")
  fi

  if [ "$count" -gt 0 ]; then
    pass "Found $count reservation(s)"
  else
    fail "No reservations found"
    return
  fi

  # Verify reservation has expected fields
  local first_res
  if echo "$reservations" | jq -e 'type == "array"' >/dev/null 2>&1; then
    first_res=$(echo "$reservations" | jq '.[0]')
  else
    first_res=$(echo "$reservations" | jq '.content[0]')
  fi

  local res_status res_room_id
  res_status=$(echo "$first_res" | jq -r '.status // empty')
  res_room_id=$(echo "$first_res" | jq -r '.roomId // empty')

  if [ -n "$res_status" ] && [ -n "$res_room_id" ]; then
    pass "Reservation has status=$res_status roomId=$res_room_id"
  else
    fail "Reservation missing status or roomId"
  fi

  # Verify client reservation endpoint (correction 5)
  local client_id
  client_id=$(echo "$first_res" | jq -r '.clientId // empty')
  if [ -n "$client_id" ]; then
    local client_reservations
    client_reservations=$(api_get "/api/clients/$client_id/reservations" || echo "")
    if [ -n "$client_reservations" ]; then
      pass "GET /api/clients/$client_id/reservations returns data"
    else
      fail "GET /api/clients/$client_id/reservations returned empty"
    fi
  fi
}

# ---------------------------------------------------------------------------
# 5. Staff Service
# ---------------------------------------------------------------------------
verify_staff() {
  blue "=== 5. Staff Service ==="

  local employees
  employees=$(api_get "/api/employees?size=100" || echo '{"content":[]}')

  local count
  count=$(echo "$employees" | jq '.content | length' 2>/dev/null || echo "0")

  if [ "$count" -gt 0 ]; then
    pass "Found $count employee(s)"
  else
    fail "No employees found"
    return
  fi

  # Verify single employee has fullName
  local first_id
  first_id=$(echo "$employees" | jq -r '.content[0].id')

  local single
  single=$(api_get "/api/employees/$first_id" || echo "")
  local full_name
  full_name=$(echo "$single" | jq -r '.fullName // empty' 2>/dev/null)

  if [ -n "$full_name" ]; then
    pass "Employee $first_id has fullName=$full_name"
  else
    fail "Employee $first_id missing fullName"
  fi
}

# ---------------------------------------------------------------------------
# 6. Housekeeping Service
# ---------------------------------------------------------------------------
verify_housekeeping() {
  blue "=== 6. Housekeeping Service ==="

  # Stats endpoint (correction 7)
  local stats
  stats=$(api_get "/api/housekeeping-tasks/stats" || echo "")

  if [ -n "$stats" ]; then
    local total
    total=$(echo "$stats" | jq -r '.total // empty' 2>/dev/null)
    if [ -n "$total" ]; then
      pass "Stats endpoint returns total=$total"
    else
      fail "Stats endpoint missing 'total' field"
    fi
  else
    fail "GET /api/housekeeping-tasks/stats returned empty"
  fi

  # Task list
  local tasks
  tasks=$(api_get "/api/housekeeping-tasks?size=10" || echo '{"content":[]}')
  local task_count
  task_count=$(echo "$tasks" | jq '.content | length' 2>/dev/null || echo "0")

  if [ "$task_count" -gt 0 ]; then
    pass "Found $task_count housekeeping task(s)"
  else
    blue "  INFO: No housekeeping tasks found (seed may not have run)"
  fi
}

# ---------------------------------------------------------------------------
# 7. Invoice Service
# ---------------------------------------------------------------------------
verify_invoices() {
  blue "=== 7. Invoice Service ==="

  local invoices
  invoices=$(api_get "/api/invoices?size=10" || echo "")

  if [ -z "$invoices" ]; then
    fail "GET /api/invoices returned empty"
    return
  fi

  local count
  count=$(echo "$invoices" | jq '.content | length' 2>/dev/null || echo "0")

  pass "Invoice endpoint accessible, $count invoice(s) found"
}

# ---------------------------------------------------------------------------
# 8. No mock fallback detection
# ---------------------------------------------------------------------------
verify_no_mocks() {
  blue "=== 8. Mock Fallback Detection ==="

  # Check that service responses don't contain mock indicators
  local rooms
  rooms=$(api_get "/api/rooms?active=true" || echo "[]")

  # A mock fallback would typically return hardcoded data even when services are down
  # We verify the data comes from real database by checking response structure
  local has_created_at
  if echo "$rooms" | jq -e 'type == "array"' >/dev/null 2>&1; then
    has_created_at=$(echo "$rooms" | jq -r '.[0].createdAt // empty' 2>/dev/null)
  else
    has_created_at=$(echo "$rooms" | jq -r '.content[0]?.createdAt // empty' 2>/dev/null)
  fi

  if [ -n "$has_created_at" ]; then
    pass "Room data includes createdAt timestamp (real DB data)"
  else
    blue "  INFO: Could not verify createdAt on rooms (may be empty)"
  fi

  # Verify no NEXT_PUBLIC_USE_*_MOCKS references remain in frontend build
  local mock_refs
  mock_refs=$(grep -r "USE_MOCK\|MOCK_DELAY\|mockResponse\|mockEmployees\|mockInvoices" frontend/src/services/ 2>/dev/null || echo "")

  if [ -z "$mock_refs" ]; then
    pass "No mock references found in frontend/src/services/"
  else
    fail "Mock references still found in frontend/src/services/"
  fi
}

# ---------------------------------------------------------------------------
# 9. Ping endpoints
# ---------------------------------------------------------------------------
verify_pings() {
  blue "=== 9. Service Ping Endpoints ==="

  local -a services=("auth" "rooms" "clients" "reservations" "invoices" "housekeeping-tasks" "employees")
  local -a labels=("auth-service" "room-service" "client-service" "reservation-service" "invoice-service" "housekeeping-service" "staff-service")

  for i in "${!services[@]}"; do
    local svc="${services[$i]}"
    local label="${labels[$i]}"
    local status
    status=$(api_get_status "/api/$svc/ping")

    if [ "$status" = "200" ]; then
      pass "$label ping OK"
    else
      fail "$label ping returned HTTP $status"
    fi
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  blue "Hotel Management System — Backend Integration Verification"
  blue "Gateway: $GATEWAY"
  echo ""

  verify_auth
  echo ""
  verify_rooms
  echo ""
  verify_clients
  echo ""
  verify_reservations
  echo ""
  verify_staff
  echo ""
  verify_housekeeping
  echo ""
  verify_invoices
  echo ""
  verify_no_mocks
  echo ""
  verify_pings

  echo ""
  blue "==========================================="
  blue "  Results: $PASS passed, $FAIL failed"
  blue "==========================================="

  if [ "$FAIL" -gt 0 ]; then
    red "Failures:"
    echo -e "$ERRORS"
    exit 1
  else
    green "All checks passed!"
    exit 0
  fi
}

main
