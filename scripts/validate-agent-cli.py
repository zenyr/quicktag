#!/usr/bin/env python3
"""Data-backed smoke checks. Pass a local CLI or SSH invocation after `--`.

Example (the command must end with `serve`):
  python scripts/validate-agent-cli.py -- quicktag-cli --packages PATH -v VERSION --cache CACHE serve

Run `index` before this script. No binary exports or package modifications occur.
The selected dataset must contain the supplied raw/localized search terms.
"""
import argparse
import json
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-query", default="bray")
    parser.add_argument("--localized-query", default="guardian")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("supply a serve command after --")
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               text=True, encoding="utf-8", bufsize=1)
    measurements = []

    def query(request, expect_ok=True):
        started = time.monotonic()
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("CLI closed stdout before responding")
        response = json.loads(line)
        assert response["schema_version"] == 1
        assert response["ok"] == expect_ok, response
        measurements.append({"op": request["op"],
                             "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                             "response_bytes": len(line.encode("utf-8"))})
        return response.get("data", response)

    try:
        first = query({"op": "tags", "limit": 3})
        second = query({"op": "tags", "offset": 3, "limit": 3})
        assert first["total"] > 3
        assert not ({x["tag"] for x in first["items"]} & {x["tag"] for x in second["items"]})
        tag = first["items"][0]["tag"]
        summary = query({"op": "tag", "hash": tag})
        data = query({"op": "bytes", "hash": tag, "length": 32})
        assert data["length"] == min(32, summary["size"])
        assert len(data["hex"]) == data["length"] * 2
        raw = query({"op": "strings", "query": args.raw_query, "limit": 3})
        localized = query({"op": "strings", "query": args.localized_query,
                           "source": "localized", "limit": 3})
        assert raw["total"] > 0 and localized["total"] > 0
        references = query({"op": "string_refs", "hash": localized["items"][0]["string_hash"],
                            "limit": 3})
        assert references["total"] > 0
        candidates = [references["items"][0]["tag"]] + [x["tag"] for x in raw["items"]]
        edge = None
        for candidate in candidates:
            outgoing = query({"op": "refs", "hash": candidate, "limit": 200})
            edge = next((x for x in outgoing["items"] if x["basis"] == "scan_match32"), None)
            if edge:
                break
        assert edge is not None, "No suitable 32-bit reference in selected candidates"
        occurrence = query({"op": "bytes", "hash": edge["source"],
                            "offset": edge["offset"], "length": 4})
        assert occurrence["hex"] == edge["target"]
        offset = 0
        while True:
            incoming = query({"op": "refs", "hash": edge["target"], "direction": "incoming",
                              "offset": offset, "limit": 200})
            if edge in incoming["items"]:
                break
            offset = incoming["next_offset"]
            assert offset is not None, "Outgoing edge is absent from incoming references"
        query({"op": "matches", "hash": edge["source"], "limit": 3})
        query({"op": "bytes", "hash": tag, "length": 4097}, expect_ok=False)
        query({"op": "info"})
        print(json.dumps({"ok": True, "tag_headers": first["total"],
                          "raw_matches": raw["total"], "localized_matches": localized["total"],
                          "edge_bytes_and_reverse_lookup": True,
                          "measurements": measurements}, indent=2))
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
