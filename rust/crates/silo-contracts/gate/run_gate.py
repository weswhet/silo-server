#!/usr/bin/env python3
"""The Rust migrator's exit gate. It runs the real Go migrator and the Rust one on identical databases.

    rust/crates/silo-contracts/gate/run_gate.py [--keep]

It proves, in a dedicated Postgres (compose.yml in this directory):

  * Fresh database: pg_dump --schema-only and goose_db_version are identical.
  * Each snapshot stopped by Go before a Go migration and seeded: finishing with Rust gives the same
    schema, goose_db_version rows, sequences, and table contents as finishing with Go. The snapshots
    are in seeds.py, along with evidence queries proving the migrations transformed the seed.
  * Two scenarios for the legacy schema_versions bootstrap and out-of-order applies.
  * Rollback through the Go migrations, on the first snapshot.

Columns are masked only when two Go runs of the same scenario differ, so timestamps from now() drop
out and nothing else does. The masks are printed and must look like timestamps and row identities.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from seeds import EVIDENCE, SNAPSHOTS

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RUST = ROOT / "rust"
CONTAINER = "silo-pg-gate-postgres-1"
PORT = 25532


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


def psql(db, sql):
    proc = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "psql", "-U", "silo", "-d", db, "-v", "ON_ERROR_STOP=1", "-At", "-q", "-f", "-"],
        input=sql, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql {db}: {proc.stderr}\n{sql[:400]}")
    return proc.stdout


def recreate(db, template=None):
    psql("silo", f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE);')
    tail = f' TEMPLATE "{template}"' if template else ""
    psql("silo", f'CREATE DATABASE "{db}"{tail};')


def url(db):
    return f"postgres://silo:silo@127.0.0.1:{PORT}/{db}?sslmode=disable"


class Runner:
    def __init__(self, name, binary):
        self.name = name
        self.binary = binary

    def __call__(self, db, *args, check=True):
        # Same working directory for both: reject reasons embed it.
        env = {**os.environ, "DATABASE_URL": url(db), "PWD": str(ROOT)}
        proc = subprocess.run([self.binary, *map(str, args)], env=env, cwd=ROOT, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise RuntimeError(f"{self.name} {args} on {db}: {proc.stderr[-2000:]}")
        return proc


def dump_schema(db):
    proc = run(["docker", "exec", CONTAINER, "pg_dump", "-U", "silo", "-d", db, "--schema-only", "--no-owner", "--restrict-key=gate"])
    return proc.stdout


def goose_rows(db):
    return psql(db, "SELECT id, version_id, is_applied FROM public.goose_db_version ORDER BY id;")


def tables(db):
    out = psql(db, """
        SELECT n.nspname || '.' || c.relname, a.attname
          FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
         WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
         ORDER BY 1, a.attnum;""")
    result = {}
    for line in out.splitlines():
        table, column = line.split("|", 1)
        result.setdefault(table, []).append(column)
    return result


def quote_table(table):
    schema, name = table.split(".", 1)
    return f'"{schema}"."{name}"'


def column_digests(db):
    """Per-table, per-column digests of the sorted column text, plus sequence positions."""
    parts = []
    for table, columns in tables(db).items():
        for column in columns:
            literal = column.replace("'", "''")
            parts.append(
                f"SELECT '{table}|{literal}|' || count(*) || '|' || coalesce(md5(string_agg(coalesce(c::text, 'NULL'), E'\\n' ORDER BY coalesce(c::text, 'NULL') COLLATE \"C\")), '') "
                f"FROM (SELECT \"{column}\" AS c FROM {quote_table(table)}) t;\n"
            )
    parts.append("SELECT 'sequence|' || schemaname || '.' || sequencename || '|' || coalesce(last_value::text, 'null') FROM pg_sequences ORDER BY 1;\n")
    out = {}
    for line in psql(db, "".join(parts)).splitlines():
        key, _, value = line.rpartition("|")
        out[key] = value
    return out


def row_digests(db, masked):
    parts = []
    for table, columns in tables(db).items():
        keep = [c for c in columns if (table, c) not in masked]
        if not keep:
            parts.append(f"SELECT '{table}|' || count(*) FROM {quote_table(table)};\n")
            continue
        cols = ", ".join(f'"{c}"' for c in keep)
        parts.append(
            f"SELECT '{table}|' || count(*) || '|' || coalesce(md5(string_agg(r, E'\\n' ORDER BY r COLLATE \"C\")), '') "
            f"FROM (SELECT ROW({cols})::text AS r FROM {quote_table(table)}) t;\n"
        )
    out = {}
    for line in psql(db, "".join(parts)).splitlines():
        table, _, value = line.partition("|")
        out[table] = value
    return out


def compare_finished(name, go_a, go_b, rust, evidence=()):
    """Go A against Go B finds the noise. Rust against Go A must then be clean."""
    failures = []

    dump_a, dump_b, dump_r = dump_schema(go_a), dump_schema(go_b), dump_schema(rust)
    if dump_a != dump_b:
        failures.append("the two Go runs differ in schema, so the scenario is not deterministic")
    if dump_a != dump_r:
        path = Path(tempfile.gettempdir()) / f"gate-{name}.diff"
        a, b = Path(tempfile.mktemp()), Path(tempfile.mktemp())
        a.write_text(dump_a)
        b.write_text(dump_r)
        path.write_text(subprocess.run(["diff", "-u", str(a), str(b)], capture_output=True, text=True).stdout)
        failures.append(f"schema differs from Go's; diff in {path}")

    if goose_rows(go_a) != goose_rows(rust):
        failures.append("goose_db_version differs from Go's")

    digests_a, digests_b = column_digests(go_a), column_digests(go_b)
    digests_r = column_digests(rust)
    masked = set()
    masked_sequences = set()
    for key, value in digests_a.items():
        if digests_b.get(key) != value:
            if key.startswith("sequence|"):
                masked_sequences.add(key)
            else:
                table, column = key.split("|")[:2]
                masked.add((table, column))
    # A column's key includes its row count, so a count difference shows up as a missing key too.
    keys_a = {k.rsplit("|", 1)[0] for k in digests_a}
    keys_r = {k.rsplit("|", 1)[0] for k in digests_r}
    if keys_a != keys_r:
        failures.append(f"table shapes differ: {sorted(keys_a ^ keys_r)[:10]}")

    # settings_backfill.go ranges over a map while it inserts rows, so the identity values in these two
    # tables pair with different rows from one Go run to the next, by chance even across two runs.
    # Their rows compare without the id, and the column digests below still check the set of ids.
    masked |= {("public.user_setting_values", "id"), ("public.user_setting_migration_rejects", "id")}
    for key, value in digests_a.items():
        if digests_b.get(key) == value and digests_r.get(key) != value:
            failures.append(f"{key}: column digest differs from Go's")
    rows_a, rows_b, rows_r = row_digests(go_a, masked), row_digests(go_b, masked), row_digests(rust, masked)
    for table, value in rows_a.items():
        if rows_b.get(table) != value:
            failures.append(f"{table}: the Go runs differ after masking, so the mask is too narrow")
        if rows_r.get(table) != value:
            failures.append(f"{table}: row digest differs from Go's")
    for key, value in digests_a.items():
        if key.startswith("sequence|") and key not in masked_sequences and digests_r.get(key) != value:
            failures.append(f"{key}: position differs from Go's ({digests_r.get(key)} vs {value})")

    for query in evidence:
        for db in (go_a, rust):
            got = psql(db, query + ";").strip()
            if got != "t":
                failures.append(f"evidence failed on {db}: {query} -> {got!r}")

    nonempty = sum(1 for v in rows_a.values() if not v.startswith("0"))
    report = {
        "scenario": name,
        "tables": len(rows_a),
        "tables_with_rows": nonempty,
        "masked_columns": sorted(f"{t}.{c}" for t, c in masked),
        "masked_sequences": sorted(masked_sequences),
        "goose_rows": len(goose_rows(rust).splitlines()),
        "failures": failures,
    }
    print(json.dumps(report), flush=True)
    return report


def finish_three(name, template, go, rust, finish=("up",)):
    go_a, go_b, rust_db = f"{name}_go_a", f"{name}_go_b", f"{name}_rust"
    for db in (go_a, go_b, rust_db):
        recreate(db, template)
    go(go_a, *finish)
    go(go_b, *finish)
    rust(rust_db, *finish)
    return go_a, go_b, rust_db


def main():
    keep = "--keep" in sys.argv
    only = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--only=")), None)
    subprocess.run(["docker", "compose", "-f", str(HERE / "compose.yml"), "up", "-d", "--wait"], check=True, capture_output=True)
    workdir = Path(tempfile.mkdtemp(prefix="silo-pg-gate-"))
    go_binary = workdir / "go-migrate"
    env = {**os.environ, "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "go1.26.7")}
    run([str(RUST / "conformance/vectors/generators/migrate/build.sh"), str(go_binary)], env=env)
    run(["cargo", "build", "-p", "silo-contracts", "--example", "migrate", "-j", "4"], cwd=RUST)
    go = Runner("go", str(go_binary))
    rust = Runner("rust", str(RUST / "target/debug/examples/migrate"))

    reports = []

    # The driver behaviors that need a server: exec modes and plans, codecs, pinned sessions.
    recreate("driver")
    subprocess.run(
        ["cargo", "test", "-p", "silo-pg", "--test", "integration", "-j", "4"],
        cwd=RUST, env={**os.environ, "SILO_PG_TEST_URL": url("driver")}, check=True,
    )

    # Fresh database.
    for db in ("fresh_go_a", "fresh_go_b", "fresh_rust"):
        recreate(db)
    go("fresh_go_a", "up")
    go("fresh_go_b", "up")
    rust("fresh_rust", "up")
    reports.append(compare_finished("fresh", "fresh_go_a", "fresh_go_b", "fresh_rust"))

    # --migrate-status reads the same database through both tools, so even the timestamps must match.
    if go("fresh_rust", "status").stdout != rust("fresh_rust", "status").stdout:
        reports.append({"scenario": "status table", "failures": ["--migrate-status output differs"]})

    # A second run applies nothing.
    before = goose_rows("fresh_rust")
    rust("fresh_rust", "up")
    if goose_rows("fresh_rust") != before:
        reports.append({"scenario": "fresh rerun", "failures": ["a second run changed goose_db_version"]})

    # Snapshots Go stopped at, seeded, then finished.
    for version, seed in SNAPSHOTS.items():
        if only and only != str(version):
            continue
        template = f"snap_{version}"
        recreate(template)
        go(template, "up-to", version)
        psql(template, seed)
        name = f"s{version}"
        go_a, go_b, rust_db = finish_three(name, template, go, rust)
        reports.append(compare_finished(name, go_a, go_b, rust_db, EVIDENCE[version]))

    if only:
        failed = [r for r in reports if r.get("failures")]
        sys.exit(1 if failed else 0)

    # Legacy schema_versions bootstrap: goose's table is gone, and the ledger holds the old numbers,
    # including versions with no source file.
    template = "snap_legacy"
    recreate(template)
    go(template, "up-to", 300)
    psql(template, """
        CREATE TABLE public.schema_versions (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT '2024-01-02 03:04:05+00');
        INSERT INTO public.schema_versions (version) SELECT version_id FROM public.goose_db_version WHERE version_id > 0;
        INSERT INTO public.schema_versions (version) VALUES (106), (129), (130), (131), (163), (164), (166) ON CONFLICT DO NOTHING;
        DROP TABLE public.goose_db_version;
    """)
    go_a, go_b, rust_db = finish_three("legacy", template, go, rust)
    reports.append(compare_finished("legacy", go_a, go_b, rust_db, ["SELECT count(*) > 7 FROM public.goose_db_version WHERE tstamp = '2024-01-02 03:04:05'"]))

    # Out-of-order: a newer version applied first, so older pending versions run below the maximum.
    template = "snap_ooo"
    recreate(template)
    go(template, "up-to", 20260911010527)
    psql(template, SNAPSHOTS[20261013231605])
    go(template, "apply", 20261014033149)
    go_a, go_b, rust_db = finish_three("ooo", template, go, rust)
    reports.append(compare_finished("ooo", go_a, go_b, rust_db, ["SELECT (SELECT max(id) FROM public.goose_db_version) > (SELECT id FROM public.goose_db_version WHERE version_id = 20261014033149)"]))

    # Rollback through the Go migrations and back up. Both tools start from the same finished
    # database, including the rows the down migrations restore.
    template = "s20260727010621_go_a"
    go_a, go_b, rust_db = finish_three("down", template, go, rust, ("down-to", 20260727010621))
    reports.append(compare_finished("down", go_a, go_b, rust_db, ["SELECT max(version_id) = 20260727010621 FROM public.goose_db_version", "SELECT count(*) > 0 FROM user_settings WHERE key LIKE 'jellycompat:%'"]))

    failed = [r for r in reports if r.get("failures")]
    print(json.dumps({"scenarios": len(reports), "failed": [r["scenario"] for r in failed]}))
    if not keep:
        subprocess.run(["docker", "compose", "-f", str(HERE / "compose.yml"), "down", "-v"], capture_output=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
