#!/usr/bin/env python3
"""Check whether CVE/product_cves rows in the vuln DB explain Qwiet-only gaps vs Mongo."""

import json
import os
import sys
from datetime import timedelta, timezone
from urllib.parse import unquote, urlparse

import psycopg2

COMPARE_JSON = os.environ.get("COMPARE_JSON", "/tmp/mongo-qwiet-cves-full.json")
DAYS = float(os.environ.get("RECENCY_DAYS", "2"))


def load_only_qwiet_cves(path: str) -> tuple[list[str], list[str]]:
    raw = open(path, encoding="utf-8").read()
    data = json.loads(raw[raw.index("{") :])
    only_qwiet: set[str] = set()
    only_mongo: set[str] = set()
    for row in data.get("rows", []):
        diff = (row.get("diff") or {}).get("cveIds") or {}
        only_qwiet.update(diff.get("onlyQwiet") or [])
        only_mongo.update(diff.get("onlyMongo") or [])
    return sorted(only_qwiet), sorted(only_mongo)


def classify(cur, ids: list[str], cutoff, label: str) -> None:
    if not ids:
        return
    cur.execute(
        """
        SELECT id, provider, internal_id, created_at, updated_at
        FROM cves
        WHERE id = ANY(%s)
        """,
        (ids,),
    )
    recs = cur.fetchall()
    found = {r[0] for r in recs}
    missing = [i for i in ids if i not in found]
    created_recent = updated_recent = 0
    by_provider: dict[str, int] = {}
    for id_, prov, _internal, created, updated in recs:
        created = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
        updated = updated if updated.tzinfo else updated.replace(tzinfo=timezone.utc)
        if created >= cutoff:
            created_recent += 1
        if updated >= cutoff:
            updated_recent += 1
        by_provider[prov] = by_provider.get(prov, 0) + 1

    print(f"\n=== cves table ({label}) ===")
    print(f"distinct_ids={len(found)} missing_in_db={len(missing)} cve_rows={len(recs)}")
    print(f"cve_rows_created_last_{DAYS}d={created_recent} cve_rows_updated_last_{DAYS}d={updated_recent}")
    print(f"by_provider={by_provider}")

    internal_ids = [r[2] for r in recs]
    cur.execute(
        """
        SELECT COUNT(*),
               COUNT(*) FILTER (WHERE created_at >= %s),
               COUNT(*) FILTER (WHERE updated_at >= %s)
        FROM product_cves
        WHERE cve_internal_id = ANY(%s)
        """,
        (cutoff, cutoff, internal_ids),
    )
    pc_total, pc_created, pc_updated = cur.fetchone()
    print(
        f"product_cves links for these CVEs: total={pc_total} "
        f"created_last_{DAYS}d={pc_created} updated_last_{DAYS}d={pc_updated}"
    )

    cur.execute(
        """
        SELECT c.id,
               MIN(c.created_at) AS c_created,
               COUNT(pc.*) AS link_count,
               COUNT(*) FILTER (WHERE pc.created_at >= %s) AS links_created_recent
        FROM cves c
        LEFT JOIN product_cves pc
          ON pc.cve_internal_id = c.internal_id AND pc.provider = c.provider
        WHERE c.id = ANY(%s)
        GROUP BY c.id
        ORDER BY links_created_recent DESC, c.id
        """,
        (cutoff, ids),
    )
    recent = old = 0
    print(f"per_cve (id, cve_created_date, links_created_{DAYS}d, total_links):")
    for cid, c_created, links, lc_recent in cur.fetchall():
        c_created = c_created if c_created.tzinfo else c_created.replace(tzinfo=timezone.utc)
        if c_created >= cutoff or (lc_recent or 0) > 0:
            recent += 1
            if recent <= 20:
                print(f"  recent {cid} {c_created.date()} links_new={lc_recent} total_links={links}")
        else:
            old += 1
    print(f"cves_explained_by_recent_ingest={recent} cves_older_ingest_only={old}")


def purl_to_product(purl: str) -> tuple[str, str]:
    """Return (language enum, product name) matching wire/sca PurlToCVEQueryCoordinate."""
    body = purl.removeprefix("pkg:").split("@", 1)[0]
    typ, rest = body.split("/", 1)
    lang = {
        "golang": "go",
        "maven": "java",
        "npm": "js",
        "nuget": "csharp",
        "pypi": "py",
        "composer": "php",
        "cargo": "rust",
    }.get(typ)
    if not lang:
        return "", ""
    if typ == "maven":
        if "/" not in rest:
            return lang, rest
        vendor, product = rest.split("/", 1)
        return lang, f"{vendor}/{product}"
    if typ == "golang":
        if "/" in rest:
            ns, name = rest.rsplit("/", 1)
            return lang, f"{ns}/{name}" if ns else name
        return lang, rest
    if typ == "nuget":
        return lang, rest.lower()
    return lang, rest


def gap_links_by_package(cur, compare_path: str, cutoff) -> None:
    raw = open(compare_path, encoding="utf-8").read()
    data = json.loads(raw[raw.index("{") :])
    print(f"\n=== gap CVE links for specific products (last {DAYS}d) ===")
    total_gaps = recent_gaps = 0
    for row in data.get("rows", []):
        diff = (row.get("diff") or {}).get("cveIds") or {}
        only_q = diff.get("onlyQwiet") or []
        if not only_q:
            continue
        lang, name = purl_to_product(row["purl"])
        if not lang:
            continue
        cur.execute(
            """
            SELECT c.id, MIN(pc.created_at), MAX(pc.created_at),
                   COUNT(*) FILTER (WHERE pc.created_at >= %s)
            FROM cves c
            JOIN product_cves pc
              ON pc.cve_internal_id = c.internal_id AND pc.provider = c.provider
            WHERE c.id = ANY(%s)
              AND pc.language = %s::language
              AND pc.name = %s
            GROUP BY c.id
            ORDER BY c.id
            """,
            (cutoff, only_q, lang, name),
        )
        recs = cur.fetchall()
        found = {r[0] for r in recs}
        missing = [c for c in only_q if c not in found]
        recent = sum(1 for r in recs if (r[3] or 0) > 0)
        total_gaps += len(only_q)
        recent_gaps += recent
        print(
            f"{row['purl']}: gap_cves={len(only_q)} linked_in_db={len(found)} "
            f"link_created_last_{DAYS}d={recent} missing_product_link={len(missing)}"
        )
        if missing and len(missing) <= 5:
            print(f"  no product_cves row for: {', '.join(missing)}")
    print(
        f"summary gap_cve_ids={total_gaps} with_package_link_created_last_{DAYS}d={recent_gaps} "
        f"({100*recent_gaps/total_gaps:.0f}% if total else 0)"
    )


def main() -> int:
    db_url = os.environ.get("VULN_DATABASE_URL")
    if not db_url:
        print("set VULN_DATABASE_URL", file=sys.stderr)
        return 2
    only_qwiet, only_mongo = load_only_qwiet_cves(COMPARE_JSON)
    print(f"from_compare only_qwiet={len(only_qwiet)} only_mongo={len(only_mongo)}")

    p = urlparse(db_url)
    conn = psycopg2.connect(
        host=p.hostname,
        port=p.port or 5432,
        dbname=p.path.lstrip("/").split("?")[0],
        user=p.username,
        password=unquote(p.password or ""),
        sslmode=os.environ.get("PGSSLMODE", "require"),
        connect_timeout=20,
    )
    cur = conn.cursor()
    cur.execute("SELECT now()")
    now = cur.fetchone()[0]
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cutoff = now - timedelta(days=DAYS)
    print(f"db_now={now.isoformat()} cutoff={cutoff.isoformat()}")

    classify(cur, only_qwiet, cutoff, "only_on_qwiet_vs_mongo")
    classify(cur, only_mongo, cutoff, "only_on_mongo_vs_qwiet")
    gap_links_by_package(cur, COMPARE_JSON, cutoff)

    cur.execute("SELECT COUNT(*) FROM cves WHERE created_at >= %s", (cutoff,))
    print(f"\nglobal cves created_last_{DAYS}d={cur.fetchone()[0]}")
    cur.execute("SELECT COUNT(*) FROM product_cves WHERE created_at >= %s", (cutoff,))
    print(f"global product_cves links created_last_{DAYS}d={cur.fetchone()[0]}")

    cur.close()
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
