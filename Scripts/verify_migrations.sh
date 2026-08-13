#!/bin/sh
set -eu

database="$(mktemp "${TMPDIR:-/tmp}/scopeproof-migrations.XXXXXX")"
trap 'rm -f "$database"' EXIT HUP INT TERM

for migration in \
  drizzle/0000_curvy_risque.sql \
  drizzle/0001_sloppy_stark_industries.sql \
  drizzle/0003_fine_wonder_man.sql \
  drizzle/0003_cooing_rhino.sql \
  drizzle/0004_cheerful_tombstone.sql \
  drizzle/0005_nappy_alice.sql \
  drizzle/0006_first_madelyne_pryor.sql \
  drizzle/0007_greedy_nextwave.sql \
  drizzle/0008_real_nebula.sql \
  drizzle/0009_chubby_martin_li.sql \
  drizzle/0010_tearful_goblin_queen.sql \
  drizzle/0011_easy_vision.sql
do
  test -f "$migration"
  sqlite3 "$database" ".read $migration"
done

test "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('assessments','audit_checkpoints','evidence_artifacts');")" = "3"
echo "Migration replay and integrity check passed."
