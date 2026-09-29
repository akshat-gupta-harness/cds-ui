#!/usr/bin/env python3
"""Read one enrichment document. Prints JSON or null. Connection comes from the environment."""

import json
import os
import sys

from pymongo import MongoClient


def main():
    uri = os.environ.get("MONGO_URI")
    if not uri:
        sys.exit("missing MONGO_URI")
    client = MongoClient(uri, serverSelectionTimeoutMS=8000)
    doc = client[os.environ.get("MONGO_DB") or "ssca"][os.environ["CDS_UI_COLLECTION"]].find_one(
        {"purl": os.environ["CDS_UI_PURL"]}
    )
    if doc is None:
        sys.stdout.write("null")
        return
    doc.pop("_id", None)
    sys.stdout.write(json.dumps(doc, default=str, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        text = str(err)
        if "Connection refused" in text:
            sys.exit("MongoDB connection refused. Start the tunnel for MONGO_URI.")
        sys.exit(f"{type(err).__name__}: {text.splitlines()[0][:300]}")
