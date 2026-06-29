#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# seed-full-demo-data.sh — destructive full demo seed for report screenshots
#
# Usage:
#   bash scripts/seed-full-demo-data.sh --yes
#
# What it does:
#   - Resets all business databases: staff, rooms, clients, reservations,
#     invoices, housekeeping.
#   - Resets auth users except the 4 RBAC demo users.
#   - Recreates enough coherent data to display all main statuses and cases.
#
# Requirements:
#   - docker compose stack databases are running.
#   - MariaDB containers use names from docker-compose.yml.
#
# This script writes directly to MariaDB. It intentionally bypasses API business
# transitions so every status can be represented for screenshots.
###############################################################################

if [[ "${1:-}" != "--yes" ]]; then
  cat >&2 <<'EOF'
Refusing to run without explicit confirmation.

This script deletes existing demo/business data from all service databases and
keeps only the 4 RBAC auth users.

Run:
  bash scripts/seed-full-demo-data.sh --yes
EOF
  exit 1
fi

AUTH_DB_ROOT_PASSWORD="${AUTH_DB_ROOT_PASSWORD:-root_hotel}"
AUTH_DB_NAME="${AUTH_DB_NAME:-db_auth}"
ROOM_DB_ROOT_PASSWORD="${ROOM_DB_ROOT_PASSWORD:-root_hotel}"
ROOM_DB_NAME="${ROOM_DB_NAME:-db_room}"
CLIENT_DB_ROOT_PASSWORD="${CLIENT_DB_ROOT_PASSWORD:-root_hotel}"
CLIENT_DB_NAME="${CLIENT_DB_NAME:-db_client}"
RESERVATION_DB_ROOT_PASSWORD="${RESERVATION_DB_ROOT_PASSWORD:-root_hotel}"
RESERVATION_DB_NAME="${RESERVATION_DB_NAME:-db_reservation}"
INVOICE_DB_ROOT_PASSWORD="${INVOICE_DB_ROOT_PASSWORD:-root_hotel}"
INVOICE_DB_NAME="${INVOICE_DB_NAME:-db_invoice}"
HOUSEKEEPING_DB_ROOT_PASSWORD="${HOUSEKEEPING_DB_ROOT_PASSWORD:-root_hotel}"
HOUSEKEEPING_DB_NAME="${HOUSEKEEPING_DB_NAME:-db_housekeeping}"
STAFF_DB_ROOT_PASSWORD="${STAFF_DB_ROOT_PASSWORD:-root_hotel}"
STAFF_DB_NAME="${STAFF_DB_NAME:-db_staff}"

blue() { printf '\033[0;34m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }

mysql_exec() {
  local service="$1"
  local database="$2"
  local password="$3"
  docker compose exec -T "$service" mariadb -uroot -p"$password" "$database"
}

mysql_scalar() {
  local service="$1"
  local database="$2"
  local password="$3"
  local query="$4"
  docker compose exec -T "$service" mariadb -N -B -uroot -p"$password" "$database" -e "$query"
}

blue "Checking database containers..."
docker compose ps db-auth db-room db-client db-reservation db-invoice db-housekeeping db-staff >/dev/null

blue "Resetting auth users, preserving only RBAC demo users..."
mysql_exec db-auth "$AUTH_DB_NAME" "$AUTH_DB_ROOT_PASSWORD" <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
DELETE FROM users
WHERE username NOT IN ('admin.test', 'manager.test', 'reception.test', 'housekeeping.test');

INSERT INTO users (username, email, password, first_name, last_name, role, active, created_at, updated_at)
VALUES
  ('admin.test', 'admin.test@hotel.com', '$2a$10$fXAZP8gjxpsETDhj2cBsj.PMRg.JhORWOuu76FXnjpZyLzxPW4IMG', 'Sara', 'El Amrani', 'ADMIN', 1, NOW(), NOW()),
  ('manager.test', 'manager.test@hotel.com', '$2a$10$bx/FTNouNgAZME/eIzfmlegZsZgqtlBKxc.Qk4fyvg6.9han.FrIy', 'Youssef', 'Bennani', 'MANAGER', 1, NOW(), NOW()),
  ('reception.test', 'reception.test@hotel.com', '$2a$10$ZhcFbrAajxHUk9fwtNOnbeXYOYW43ya77S4e3LfgguPc80IR0K7Nq', 'Salma', 'Idrissi', 'RECEPTIONIST', 1, NOW(), NOW()),
  ('housekeeping.test', 'housekeeping.test@hotel.com', '$2a$10$1U.HL0HTpP9EBA.wJuTuH.TdZYn8aA3.tErDO96Ls5CGo79HEsHzG', 'Hamza', 'Alaoui', 'HOUSEKEEPING_AGENT', 1, NOW(), NOW())
ON DUPLICATE KEY UPDATE
  email = VALUES(email),
  password = VALUES(password),
  first_name = VALUES(first_name),
  last_name = VALUES(last_name),
  role = VALUES(role),
  active = 1,
  updated_at = NOW();

SET FOREIGN_KEY_CHECKS = 1;
SQL

ADMIN_ID="$(mysql_scalar db-auth "$AUTH_DB_NAME" "$AUTH_DB_ROOT_PASSWORD" "SELECT id FROM users WHERE username='admin.test' LIMIT 1;")"
MANAGER_ID="$(mysql_scalar db-auth "$AUTH_DB_NAME" "$AUTH_DB_ROOT_PASSWORD" "SELECT id FROM users WHERE username='manager.test' LIMIT 1;")"
RECEPTION_ID="$(mysql_scalar db-auth "$AUTH_DB_NAME" "$AUTH_DB_ROOT_PASSWORD" "SELECT id FROM users WHERE username='reception.test' LIMIT 1;")"
HOUSEKEEPING_ID="$(mysql_scalar db-auth "$AUTH_DB_NAME" "$AUTH_DB_ROOT_PASSWORD" "SELECT id FROM users WHERE username='housekeeping.test' LIMIT 1;")"

blue "Resetting rooms..."
mysql_exec db-room "$ROOM_DB_NAME" "$ROOM_DB_ROOT_PASSWORD" <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE rooms;
ALTER TABLE rooms AUTO_INCREMENT = 1;

INSERT INTO rooms (id, number, floor, type, price_per_night, capacity, status, description, active, created_at, updated_at)
VALUES
  (1, '101', 1, 'SINGLE', 650.00, 1, 'AVAILABLE', 'Single calme côté patio, idéale court séjour.', 1, NOW(), NOW()),
  (2, '102', 1, 'DOUBLE', 920.00, 2, 'RESERVED', 'Double standard réservée pour arrivée du jour.', 1, NOW(), NOW()),
  (3, '103', 1, 'TWIN', 880.00, 2, 'OCCUPIED', 'Twin occupée, check-out prévu demain.', 1, NOW(), NOW()),
  (4, '104', 1, 'DOUBLE', 900.00, 2, 'CLEANING', 'Double en nettoyage après départ.', 1, NOW(), NOW()),
  (5, '105', 1, 'SINGLE', 610.00, 1, 'MAINTENANCE', 'Climatisation à contrôler.', 1, NOW(), NOW()),
  (6, '106', 1, 'DOUBLE', 860.00, 2, 'OUT_OF_SERVICE', 'Chambre bloquée pour rénovation légère.', 1, NOW(), NOW()),
  (7, '201', 2, 'SUITE', 1850.00, 2, 'AVAILABLE', 'Suite junior avec salon.', 1, NOW(), NOW()),
  (8, '202', 2, 'FAMILY', 1600.00, 4, 'RESERVED', 'Familiale réservée pour séjour long.', 1, NOW(), NOW()),
  (9, '203', 2, 'DELUXE', 1450.00, 2, 'OCCUPIED', 'Deluxe vue ville.', 1, NOW(), NOW()),
  (10, '204', 2, 'DOUBLE', 970.00, 2, 'AVAILABLE', 'Double supérieure.', 1, NOW(), NOW()),
  (11, '205', 2, 'TWIN', 910.00, 2, 'CLEANING', 'Inspection literie en cours.', 1, NOW(), NOW()),
  (12, '206', 2, 'SINGLE', 690.00, 1, 'AVAILABLE', 'Single premium.', 1, NOW(), NOW()),
  (13, '301', 3, 'SUITE', 2400.00, 3, 'AVAILABLE', 'Suite exécutive avec terrasse.', 1, NOW(), NOW()),
  (14, '302', 3, 'DELUXE', 1500.00, 2, 'RESERVED', 'Deluxe réservée VIP.', 1, NOW(), NOW()),
  (15, '303', 3, 'FAMILY', 1750.00, 5, 'OCCUPIED', 'Familiale occupée.', 1, NOW(), NOW()),
  (16, '304', 3, 'DOUBLE', 980.00, 2, 'MAINTENANCE', 'Robinetterie salle de bain.', 1, NOW(), NOW()),
  (17, '305', 3, 'SINGLE', 700.00, 1, 'AVAILABLE', 'Single longue durée.', 1, NOW(), NOW()),
  (18, '306', 3, 'TWIN', 940.00, 2, 'AVAILABLE', 'Twin calme.', 0, NOW(), NOW());
SET FOREIGN_KEY_CHECKS = 1;
SQL

blue "Resetting clients..."
mysql_exec db-client "$CLIENT_DB_NAME" "$CLIENT_DB_ROOT_PASSWORD" <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE clients;
ALTER TABLE clients AUTO_INCREMENT = 1;

INSERT INTO clients (id, first_name, last_name, email, phone, cin, passport_number, nationality, address, birth_date, active, created_at, updated_at)
VALUES
  (1, 'Noura', 'Bakkali', 'noura.bakkali@example.com', '+212600100001', 'BK100001', 'PMA100001', 'Marocaine', 'Casablanca, Maarif', '1988-04-12', 1, NOW(), NOW()),
  (2, 'Omar', 'Tazi', 'omar.tazi@example.com', '+212600100002', 'TZ100002', 'PMA100002', 'Marocaine', 'Rabat, Agdal', '1982-09-25', 1, NOW(), NOW()),
  (3, 'Leila', 'El Fassi', 'leila.elfassi@example.com', '+212600100003', 'EF100003', 'PMA100003', 'Marocaine', 'Fes, Batha', '1994-01-08', 1, NOW(), NOW()),
  (4, 'Adam', 'Mansouri', 'adam.mansouri@example.com', '+212600100004', 'MN100004', 'PMA100004', 'Marocaine', 'Marrakech, Gueliz', '1979-06-19', 1, NOW(), NOW()),
  (5, 'Sofia', 'Bennani', 'sofia.bennani@example.com', '+212600100005', 'BN100005', 'PMA100005', 'Marocaine', 'Tanger, Iberia', '1991-11-02', 1, NOW(), NOW()),
  (6, 'Yassine', 'Amrani', 'yassine.amrani@example.com', '+212600100006', 'AM100006', 'PMA100006', 'Marocaine', 'Agadir, Talborjt', '1986-03-17', 1, NOW(), NOW()),
  (7, 'Camille', 'Durand', 'camille.durand@example.com', '+33601020304', NULL, 'FR700001', 'Française', 'Paris, France', '1990-07-30', 1, NOW(), NOW()),
  (8, 'Marco', 'Rossi', 'marco.rossi@example.com', '+393331112233', NULL, 'IT800001', 'Italienne', 'Milan, Italie', '1984-12-14', 1, NOW(), NOW()),
  (9, 'Amina', 'Idrissi', 'amina.idrissi@example.com', '+212600100009', 'ID100009', 'PMA100009', 'Marocaine', 'Oujda, Centre', '1997-05-05', 1, NOW(), NOW()),
  (10, 'Karim', 'Ziani', 'karim.ziani@example.com', '+212600100010', 'ZI100010', 'PMA100010', 'Marocaine', 'Casablanca, Bourgogne', '1975-02-23', 1, NOW(), NOW()),
  (11, 'Hind', 'Serraj', 'hind.serraj@example.com', '+212600100011', 'SR100011', 'PMA100011', 'Marocaine', 'Kenitra', '1992-10-11', 0, NOW(), NOW()),
  (12, 'Lucas', 'Martin', 'lucas.martin@example.com', '+33622223333', NULL, 'FR700002', 'Française', 'Lyon, France', '1989-08-04', 1, NOW(), NOW());
SET FOREIGN_KEY_CHECKS = 1;
SQL

blue "Resetting reservations..."
mysql_exec db-reservation "$RESERVATION_DB_NAME" "$RESERVATION_DB_ROOT_PASSWORD" <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE reservations;
ALTER TABLE reservations AUTO_INCREMENT = 1;

INSERT INTO reservations (id, room_id, client_id, check_in_date, check_out_date, status, total_price, notes, reference, active, created_at, updated_at)
VALUES
  (1, 2, 1, CURDATE(), DATE_ADD(CURDATE(), INTERVAL 2 DAY), 'CREATED', 1840.00, 'Arrivée tardive, lit bébé demandé.', 'HMS-2026-000001', 1, NOW(), NOW()),
  (2, 8, 2, DATE_ADD(CURDATE(), INTERVAL 1 DAY), DATE_ADD(CURDATE(), INTERVAL 6 DAY), 'CONFIRMED', 8000.00, 'Famille avec deux enfants.', 'HMS-2026-000002', 1, NOW(), NOW()),
  (3, 3, 3, DATE_SUB(CURDATE(), INTERVAL 1 DAY), DATE_ADD(CURDATE(), INTERVAL 1 DAY), 'CHECKED_IN', 1760.00, 'Check-in effectué, paiement à la sortie.', 'HMS-2026-000003', 1, NOW(), NOW()),
  (4, 9, 4, DATE_SUB(CURDATE(), INTERVAL 3 DAY), DATE_SUB(CURDATE(), INTERVAL 1 DAY), 'CHECKED_OUT', 2900.00, 'Client régulier, facture payée.', 'HMS-2026-000004', 1, NOW(), NOW()),
  (5, 14, 5, DATE_ADD(CURDATE(), INTERVAL 3 DAY), DATE_ADD(CURDATE(), INTERVAL 5 DAY), 'CANCELLED', 3000.00, 'Annulation client avant arrivée.', 'HMS-2026-000005', 1, NOW(), NOW()),
  (6, 10, 6, DATE_SUB(CURDATE(), INTERVAL 1 DAY), CURDATE(), 'NO_SHOW', 970.00, 'Client non présenté.', 'HMS-2026-000006', 1, NOW(), NOW()),
  (7, 13, 7, DATE_ADD(CURDATE(), INTERVAL 7 DAY), DATE_ADD(CURDATE(), INTERVAL 10 DAY), 'CONFIRMED', 7200.00, 'VIP, accueil personnalisé.', 'HMS-2026-000007', 1, NOW(), NOW()),
  (8, 1, 8, DATE_ADD(CURDATE(), INTERVAL 2 DAY), DATE_ADD(CURDATE(), INTERVAL 3 DAY), 'CREATED', 650.00, 'Réservation web à confirmer.', 'HMS-2026-000008', 1, NOW(), NOW()),
  (9, 15, 9, DATE_SUB(CURDATE(), INTERVAL 2 DAY), DATE_ADD(CURDATE(), INTERVAL 2 DAY), 'CHECKED_IN', 7000.00, 'Séjour familial en cours.', 'HMS-2026-000009', 1, NOW(), NOW()),
  (10, 7, 10, DATE_SUB(CURDATE(), INTERVAL 8 DAY), DATE_SUB(CURDATE(), INTERVAL 5 DAY), 'CHECKED_OUT', 5550.00, 'Départ terminé, facture émise.', 'HMS-2026-000010', 1, NOW(), NOW()),
  (11, 12, 12, DATE_ADD(CURDATE(), INTERVAL 10 DAY), DATE_ADD(CURDATE(), INTERVAL 12 DAY), 'CONFIRMED', 1380.00, 'Client étranger, passeport vérifié.', 'HMS-2026-000011', 1, NOW(), NOW()),
  (12, 4, 11, DATE_SUB(CURDATE(), INTERVAL 20 DAY), DATE_SUB(CURDATE(), INTERVAL 18 DAY), 'CANCELLED', 1800.00, 'Ancienne réservation annulée.', 'HMS-2026-000012', 0, NOW(), NOW());
SET FOREIGN_KEY_CHECKS = 1;
SQL

blue "Resetting staff and linking RBAC users..."
mysql_exec db-staff "$STAFF_DB_NAME" "$STAFF_DB_ROOT_PASSWORD" <<SQL
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE employees;
ALTER TABLE employees AUTO_INCREMENT = 1;

INSERT INTO employees (id, first_name, last_name, email, phone, cin, department, active, deleted, auth_user_id, created_at, updated_at)
VALUES
  (1, 'Sara', 'El Amrani', 'sara.elamrani@hotel.com', '+212600200001', 'STF100001', 'MANAGEMENT', 1, 0, ${ADMIN_ID}, NOW(), NOW()),
  (2, 'Youssef', 'Bennani', 'youssef.bennani@hotel.com', '+212600200002', 'STF100002', 'MANAGEMENT', 1, 0, ${MANAGER_ID}, NOW(), NOW()),
  (3, 'Salma', 'Idrissi', 'salma.idrissi@hotel.com', '+212600200003', 'STF100003', 'RECEPTION', 1, 0, ${RECEPTION_ID}, NOW(), NOW()),
  (4, 'Hamza', 'Alaoui', 'hamza.alaoui@hotel.com', '+212600200004', 'STF100004', 'HOUSEKEEPING', 1, 0, ${HOUSEKEEPING_ID}, NOW(), NOW()),
  (5, 'Fatima', 'Zahra', 'fatima.zahra@hotel.com', '+212600200005', 'STF100005', 'HOUSEKEEPING', 1, 0, NULL, NOW(), NOW()),
  (6, 'Hassan', 'Moukrim', 'hassan.moukrim@hotel.com', '+212600200006', 'STF100006', 'HOUSEKEEPING', 1, 0, NULL, NOW(), NOW()),
  (7, 'Nadia', 'Oukacha', 'nadia.oukacha@hotel.com', '+212600200007', 'STF100007', 'RECEPTION', 1, 0, NULL, NOW(), NOW()),
  (8, 'Rachid', 'Kabbaj', 'rachid.kabbaj@hotel.com', '+212600200008', 'STF100008', 'MAINTENANCE', 1, 0, NULL, NOW(), NOW()),
  (9, 'Imane', 'Lahlou', 'imane.lahlou@hotel.com', '+212600200009', 'STF100009', 'KITCHEN', 1, 0, NULL, NOW(), NOW()),
  (10, 'Meryem', 'Sefrioui', 'meryem.sefrioui@hotel.com', '+212600200010', 'STF100010', 'HR', 1, 0, NULL, NOW(), NOW()),
  (11, 'Anas', 'Berrada', 'anas.berrada@hotel.com', '+212600200011', 'STF100011', 'SECURITY', 0, 0, NULL, NOW(), NOW()),
  (12, 'Khalid', 'Rami', 'khalid.rami@hotel.com', '+212600200012', 'STF100012', 'HOUSEKEEPING', 0, 1, NULL, NOW(), NOW());
SET FOREIGN_KEY_CHECKS = 1;
SQL

blue "Resetting invoices..."
mysql_exec db-invoice "$INVOICE_DB_NAME" "$INVOICE_DB_ROOT_PASSWORD" <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
DELETE FROM invoice_lines;
DELETE FROM invoices;
ALTER TABLE invoices AUTO_INCREMENT = 1;
ALTER TABLE invoice_lines AUTO_INCREMENT = 1;

INSERT INTO invoices (
  id, invoice_number, reservation_id, client_id, client_full_name, room_id, room_number,
  check_in_date, check_out_date, nights, price_per_night, subtotal_amount, tax_rate,
  tax_amount, total_amount, status, payment_method, payment_reference, notes,
  cancellation_reason, refund_reason, issued_at, paid_at, cancelled_at, refunded_at,
  created_at, updated_at
) VALUES
  (1, 'INV-2026-0001', 1, 1, 'Noura Bakkali', 2, '102', CURDATE(), DATE_ADD(CURDATE(), INTERVAL 2 DAY), 2, 920.00, 1840.00, 10.00, 184.00, 2024.00, 'DRAFT', NULL, NULL, 'Brouillon généré avant confirmation.', NULL, NULL, NULL, NULL, NULL, NULL, NOW(), NOW()),
  (2, 'INV-2026-0002', 2, 2, 'Omar Tazi', 8, '202', DATE_ADD(CURDATE(), INTERVAL 1 DAY), DATE_ADD(CURDATE(), INTERVAL 6 DAY), 5, 1600.00, 8000.00, 10.00, 800.00, 8800.00, 'ISSUED', NULL, NULL, 'Facture émise, paiement attendu.', NULL, NULL, NOW(), NULL, NULL, NULL, NOW(), NOW()),
  (3, 'INV-2026-0003', 4, 4, 'Adam Mansouri', 9, '203', DATE_SUB(CURDATE(), INTERVAL 3 DAY), DATE_SUB(CURDATE(), INTERVAL 1 DAY), 2, 1450.00, 2900.00, 10.00, 290.00, 3190.00, 'PAID', 'CARD', 'TPE-778245', 'Paiement carte bancaire.', NULL, NULL, DATE_SUB(NOW(), INTERVAL 2 DAY), DATE_SUB(NOW(), INTERVAL 1 DAY), NULL, NULL, NOW(), NOW()),
  (4, 'INV-2026-0004', 5, 5, 'Sofia Bennani', 14, '302', DATE_ADD(CURDATE(), INTERVAL 3 DAY), DATE_ADD(CURDATE(), INTERVAL 5 DAY), 2, 1500.00, 3000.00, 10.00, 300.00, 3300.00, 'CANCELLED', NULL, NULL, 'Facture annulée suite annulation réservation.', 'Réservation annulée par le client.', NULL, DATE_SUB(NOW(), INTERVAL 1 DAY), NULL, NOW(), NULL, NOW(), NOW()),
  (5, 'INV-2026-0005', 10, 10, 'Karim Ziani', 7, '201', DATE_SUB(CURDATE(), INTERVAL 8 DAY), DATE_SUB(CURDATE(), INTERVAL 5 DAY), 3, 1850.00, 5550.00, 10.00, 555.00, 6105.00, 'REFUNDED', 'BANK_TRANSFER', 'VIR-2026-4100', 'Remboursement partiel relation client.', NULL, 'Geste commercial après incident technique.', DATE_SUB(NOW(), INTERVAL 7 DAY), DATE_SUB(NOW(), INTERVAL 6 DAY), NULL, DATE_SUB(NOW(), INTERVAL 2 DAY), NOW(), NOW()),
  (6, 'INV-2026-0006', 3, 3, 'Leila El Fassi', 3, '103', DATE_SUB(CURDATE(), INTERVAL 1 DAY), DATE_ADD(CURDATE(), INTERVAL 1 DAY), 2, 880.00, 1760.00, 10.00, 176.00, 1936.00, 'ISSUED', NULL, NULL, 'Séjour en cours, facture pro forma.', NULL, NULL, NOW(), NULL, NULL, NULL, NOW(), NOW()),
  (7, 'INV-2026-0007', 9, 9, 'Amina Idrissi', 15, '303', DATE_SUB(CURDATE(), INTERVAL 2 DAY), DATE_ADD(CURDATE(), INTERVAL 2 DAY), 4, 1750.00, 7000.00, 10.00, 700.00, 7700.00, 'PAID', 'CASH', 'CASH-2026-091', 'Acompte encaissé en espèces.', NULL, NULL, NOW(), NOW(), NULL, NULL, NOW(), NOW()),
  (8, 'INV-2026-0008', 6, 6, 'Yassine Amrani', 10, '204', DATE_SUB(CURDATE(), INTERVAL 1 DAY), CURDATE(), 1, 970.00, 970.00, 10.00, 97.00, 1067.00, 'CANCELLED', NULL, NULL, 'No-show non facturé.', 'No-show annulé sans frais.', NULL, NOW(), NULL, NOW(), NULL, NOW(), NOW());

INSERT INTO invoice_lines (invoice_id, type, description, quantity, unit_price, line_total)
VALUES
  (1, 'ROOM_STAY', 'Séjour chambre 102 - 2 nuits', 2, 920.00, 1840.00),
  (2, 'ROOM_STAY', 'Séjour chambre 202 - 5 nuits', 5, 1600.00, 8000.00),
  (2, 'EXTRA_SERVICE', 'Petit-déjeuner famille', 5, 180.00, 900.00),
  (3, 'ROOM_STAY', 'Séjour chambre 203 - 2 nuits', 2, 1450.00, 2900.00),
  (3, 'EXTRA_SERVICE', 'Service spa', 1, 450.00, 450.00),
  (3, 'DISCOUNT', 'Remise client fidèle', 1, -160.00, -160.00),
  (4, 'ROOM_STAY', 'Séjour chambre 302 - 2 nuits', 2, 1500.00, 3000.00),
  (5, 'ROOM_STAY', 'Séjour suite 201 - 3 nuits', 3, 1850.00, 5550.00),
  (6, 'ROOM_STAY', 'Séjour chambre 103 - 2 nuits', 2, 880.00, 1760.00),
  (7, 'ROOM_STAY', 'Séjour chambre 303 - 4 nuits', 4, 1750.00, 7000.00),
  (7, 'EXTRA_SERVICE', 'Parking sécurisé', 4, 70.00, 280.00),
  (8, 'ROOM_STAY', 'No-show chambre 204', 1, 970.00, 970.00);
SET FOREIGN_KEY_CHECKS = 1;
SQL

blue "Resetting housekeeping tasks..."
mysql_exec db-housekeeping "$HOUSEKEEPING_DB_NAME" "$HOUSEKEEPING_DB_ROOT_PASSWORD" <<'SQL'
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE housekeeping_tasks;
ALTER TABLE housekeeping_tasks AUTO_INCREMENT = 1;

INSERT INTO housekeeping_tasks (
  id, room_id, room_number, reservation_id, assigned_agent_id, assigned_agent_name,
  type, status, priority, scheduled_date, started_at, completed_at, cancelled_at,
  cancellation_reason, notes, created_at, updated_at
) VALUES
  (1, 4, '104', NULL, 4, 'Hamza Alaoui', 'STANDARD_CLEANING', 'TODO', 'HIGH', CURDATE(), NULL, NULL, NULL, NULL, 'Départ ce matin, chambre à remettre en vente.', NOW(), NOW()),
  (2, 11, '205', NULL, 4, 'Hamza Alaoui', 'INSPECTION', 'IN_PROGRESS', 'MEDIUM', CURDATE(), DATE_SUB(NOW(), INTERVAL 45 MINUTE), NULL, NULL, NULL, 'Inspection literie et minibar.', NOW(), NOW()),
  (3, 3, '103', 3, 5, 'Fatima Zahra', 'STANDARD_CLEANING', 'DONE', 'LOW', DATE_SUB(CURDATE(), INTERVAL 1 DAY), DATE_SUB(NOW(), INTERVAL 1 DAY), DATE_SUB(NOW(), INTERVAL 23 HOUR), NULL, NULL, 'Nettoyage quotidien terminé.', NOW(), NOW()),
  (4, 5, '105', NULL, 6, 'Hassan Moukrim', 'LIGHT_MAINTENANCE', 'CANCELLED', 'URGENT', CURDATE(), NULL, NULL, NOW(), 'Doublon avec intervention maintenance.', 'À replanifier avec technicien.', NOW(), NOW()),
  (5, 15, '303', 9, 4, 'Hamza Alaoui', 'DEEP_CLEANING', 'TODO', 'URGENT', CURDATE(), NULL, NULL, NULL, NULL, 'Famille en séjour, nettoyage approfondi demandé.', NOW(), NOW()),
  (6, 9, '203', 4, 5, 'Fatima Zahra', 'STANDARD_CLEANING', 'DONE', 'MEDIUM', DATE_SUB(CURDATE(), INTERVAL 1 DAY), DATE_SUB(NOW(), INTERVAL 26 HOUR), DATE_SUB(NOW(), INTERVAL 25 HOUR), NULL, NULL, 'Après check-out.', NOW(), NOW()),
  (7, 16, '304', NULL, 8, 'Rachid Kabbaj', 'LIGHT_MAINTENANCE', 'IN_PROGRESS', 'HIGH', CURDATE(), DATE_SUB(NOW(), INTERVAL 2 HOUR), NULL, NULL, NULL, 'Robinetterie salle de bain.', NOW(), NOW()),
  (8, 13, '301', 7, NULL, NULL, 'INSPECTION', 'TODO', 'MEDIUM', DATE_ADD(CURDATE(), INTERVAL 1 DAY), NULL, NULL, NULL, NULL, 'Inspection pré-arrivée VIP non assignée.', NOW(), NOW()),
  (9, 2, '102', 1, 4, 'Hamza Alaoui', 'STANDARD_CLEANING', 'TODO', 'MEDIUM', DATE_ADD(CURDATE(), INTERVAL 2 DAY), NULL, NULL, NULL, NULL, 'Préparation prochaine arrivée.', NOW(), NOW()),
  (10, 8, '202', 2, 5, 'Fatima Zahra', 'DEEP_CLEANING', 'TODO', 'HIGH', DATE_ADD(CURDATE(), INTERVAL 5 DAY), NULL, NULL, NULL, NULL, 'Préparation séjour famille.', NOW(), NOW()),
  (11, 6, '106', NULL, NULL, NULL, 'INSPECTION', 'CANCELLED', 'LOW', DATE_SUB(CURDATE(), INTERVAL 2 DAY), NULL, NULL, DATE_SUB(NOW(), INTERVAL 2 DAY), 'Chambre sortie du périmètre vente.', 'Rénovation planifiée.', NOW(), NOW()),
  (12, 10, '204', 6, 6, 'Hassan Moukrim', 'STANDARD_CLEANING', 'DONE', 'HIGH', DATE_SUB(CURDATE(), INTERVAL 1 DAY), DATE_SUB(NOW(), INTERVAL 20 HOUR), DATE_SUB(NOW(), INTERVAL 19 HOUR), NULL, NULL, 'No-show traité, chambre disponible.', NOW(), NOW());
SET FOREIGN_KEY_CHECKS = 1;
SQL

green "Full demo seed completed."
cat <<EOF

RBAC accounts:
  ADMIN              admin.test        / Admin@123
  MANAGER            manager.test      / Manager@123
  RECEPTIONIST       reception.test    / Reception@123
  HOUSEKEEPING_AGENT housekeeping.test / Housekeeping@123

Seed summary:
  - Rooms: all statuses and all room types
  - Clients: active and inactive profiles
  - Reservations: CREATED, CONFIRMED, CHECKED_IN, CHECKED_OUT, CANCELLED, NO_SHOW
  - Invoices: DRAFT, ISSUED, PAID, CANCELLED, REFUNDED with payment methods and line types
  - Housekeeping: TODO, IN_PROGRESS, DONE, CANCELLED with all priorities/types
  - Staff: departments, active/inactive/deleted examples, RBAC users linked
EOF
