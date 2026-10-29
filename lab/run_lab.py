#!/usr/bin/env python3
"""
End-to-end lab: load EVERY fixture event into Elastic, Kusto (Sentinel's KQL engine)
and Splunk, run the shipped queries from conversions/, and require each engine to
return exactly the events the reference evaluator (tests/sigma_eval.py) matches over
the whole corpus. That catches misses, false positives on other rules' traffic and
conversion bugs (quoting, case, regex dialect) that unit tests cannot see.

Stdlib only, plus PyYAML for the reference evaluator. Exit code != 0 on any mismatch.
"""
import base64
import json
import os
import pathlib
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from sigma_eval import load_rule, matching_indices  # noqa: E402

TABLE = "AIAgentRuntime_CL"
INDEX = "detlab"
SOURCETYPE = "detlab_json"
RUN = f"run{int(time.time())}"  # tags this run's events, so a reused Splunk never answers with stale ones
NO_TLS = ssl._create_unverified_context()  # lab only: Splunk's self-signed cert on 127.0.0.1


# --------------------------------------------------------------------------- #
# Corpus and reference results                                                #
# --------------------------------------------------------------------------- #
def load_corpus():
    events = []
    for kind_file in sorted((ROOT / "fixtures").glob("*/*.json")):
        data = json.loads(kind_file.read_text(encoding="utf-8"))
        for i, ev in enumerate(data if isinstance(data, list) else [data]):
            ev = dict(ev)
            ev["fixture_id"] = f"{kind_file.parent.name}/{kind_file.stem}/{i}"
            events.append(ev)
    return events


def reference(rules, events):
    return {name: {events[i]["fixture_id"] for i in matching_indices(rule, events)}
            for name, rule in rules.items()}


# --------------------------------------------------------------------------- #
# HTTP helper                                                                 #
# --------------------------------------------------------------------------- #
def http(method, url, body=None, headers=None, ctx=None, form=False):
    data = None
    headers = dict(headers or {})
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def wait_for(name, check, timeout=600):
    start = time.time()
    while time.time() - start < timeout:
        try:
            if check():
                print(f"  {name}: up ({int(time.time() - start)} s)")
                return
        except Exception:
            pass
        time.sleep(5)
    raise SystemExit(f"{name} did not come up in {timeout} s")


# --------------------------------------------------------------------------- #
# Elastic (ES|QL)                                                             #
# --------------------------------------------------------------------------- #
ES = "http://127.0.0.1:9200"


def elastic_load(events):
    wait_for("elastic", lambda: http("GET", ES)[0] == 200)
    http("DELETE", f"{ES}/{INDEX}")
    # subobjects:false keeps dotted keys flat, so `content` and `content.scanner_verdict`
    # (or `agent` and `agent.spawn_depth`) can coexist; strings map to keyword.
    mapping = {"mappings": {"subobjects": False, "dynamic_templates": [
        {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}]}}
    st, out = http("PUT", f"{ES}/{INDEX}", mapping)
    assert st == 200, out
    bulk = "".join(json.dumps({"index": {}}) + "\n" + json.dumps(ev) + "\n" for ev in events)
    st, out = http("POST", f"{ES}/{INDEX}/_bulk?refresh=true", bulk.encode(),
                   {"Content-Type": "application/x-ndjson"})
    assert st == 200 and not json.loads(out)["errors"], out[:2000]


def elastic_run(query):
    q = re.sub(r"^from \* metadata [^|]*", f"from {INDEX} metadata _id ", query.strip())
    q += " | keep fixture_id | limit 10000"
    st, out = http("POST", f"{ES}/_query", {"query": q})
    if st != 200:
        raise RuntimeError(json.loads(out).get("error", {}).get("reason", out)[:300])
    return {row[0] for row in json.loads(out)["values"]}


# --------------------------------------------------------------------------- #
# Kusto emulator (KQL, as in Microsoft Sentinel)                              #
# --------------------------------------------------------------------------- #
KU = "http://127.0.0.1:8080"


def kusto(csl, mgmt=False):
    st, out = http("POST", f"{KU}/v1/rest/{'mgmt' if mgmt else 'query'}",
                   {"db": "NetDefaultDB", "csl": csl})
    if st != 200:
        raise RuntimeError(out[:300])
    return json.loads(out)


def _kql_type(values):
    vals = [v for v in values if v is not None]
    if vals and all(isinstance(v, bool) for v in vals):
        return "bool"
    if vals and all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return "long"
    if vals and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return "real"
    return "string"


def kusto_load(events):
    wait_for("kusto", lambda: kusto("print 1") is not None)
    fields = sorted({k for ev in events for k in ev})
    cols = {f: _kql_type([ev.get(f) for ev in events]) for f in fields}
    col = {f: f.replace(".", "_") for f in fields}   # same mapping as pipelines/sentinel.yml
    kusto(f".drop table {TABLE} ifexists", mgmt=True)
    kusto(f".create table {TABLE} (" + ", ".join(f"['{col[f]}']:{cols[f]}" for f in fields) + ")",
          mgmt=True)
    rows = ", ".join('@"' + json.dumps(ev).replace('"', '""') + '"' for ev in events)
    conv = ", ".join(f"['{col[f]}']=to{cols[f]}(d['{f}'])" for f in fields)
    kusto(f".set-or-append {TABLE} <| datatable(j:string)[{rows}] "
          f"| extend d=parse_json(j) | project {conv}", mgmt=True)
    n = kusto(f"{TABLE} | count")["Tables"][0]["Rows"][0][0]
    assert n == len(events), f"kusto loaded {n} of {len(events)}"


def kusto_run(query):
    res = kusto(query.strip() + "\n| project fixture_id")
    return {row[0] for row in res["Tables"][0]["Rows"]}


# --------------------------------------------------------------------------- #
# Splunk (SPL)                                                                #
# --------------------------------------------------------------------------- #
SP = "https://127.0.0.1:8089"
HEC = "https://127.0.0.1:8088"


def _sp_auth():
    tok = base64.b64encode(f"admin:{os.environ['SPLUNK_PASSWORD']}".encode()).decode()
    return {"Authorization": f"Basic {tok}"}


def _sp_search(spl):
    st, out = http("POST", f"{SP}/services/search/jobs/export",
                   {"search": spl, "output_mode": "json", "earliest_time": "0"},
                   _sp_auth(), NO_TLS, form=True)
    if st != 200:
        raise RuntimeError(out[:300])
    rows = [json.loads(line) for line in out.splitlines() if line.strip()]
    for r in rows:
        if r.get("messages") and any(m.get("type") in ("ERROR", "FATAL") for m in r["messages"]):
            raise RuntimeError(str(r["messages"])[:300])
    return [r["result"] for r in rows if "result" in r]


def splunk_load(events):
    wait_for("splunk", lambda: http("GET", f"{SP}/services/server/info", headers=_sp_auth(),
                                    ctx=NO_TLS)[0] == 200)
    # search-time JSON extraction, so dotted keys become fields named exactly like the rules
    http("POST", f"{SP}/servicesNS/nobody/search/configs/conf-props",
         {"name": SOURCETYPE, "KV_MODE": "json", "SHOULD_LINEMERGE": "false"},
         _sp_auth(), NO_TLS, form=True)
    hec = {"Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}"}
    wait_for("splunk HEC", lambda: http("GET", f"{HEC}/services/collector/health",
                                        ctx=NO_TLS)[0] == 200)
    payload = "".join(json.dumps({"event": dict(ev, lab_run=RUN), "sourcetype": SOURCETYPE,
                                  "index": "main"}) for ev in events)
    st, out = http("POST", f"{HEC}/services/collector/event", payload.encode(), hec, NO_TLS)
    assert st == 200, out
    base = f"search index=main sourcetype={SOURCETYPE} lab_run={RUN}"
    wait_for("splunk indexing", lambda: int(_sp_search(f"{base} | stats dc(fixture_id) as n")[0]["n"])
             == len(events), timeout=180)


def splunk_run(query):
    q = re.sub(r"\|\s*table [^|]*$", "", query.strip()).strip()
    spl = f"search index=main sourcetype={SOURCETYPE} lab_run={RUN} {q} | table fixture_id"
    return {r["fixture_id"] for r in _sp_search(spl)}


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
ENGINES = {
    "elastic-esql": (elastic_load, elastic_run, "elastic-esql", "esql"),
    "sentinel-kql": (kusto_load, kusto_run, "sentinel", "kql"),
    "splunk-spl": (splunk_load, splunk_run, "splunk", "spl"),
}


def main():
    only = sys.argv[1:] or list(ENGINES)
    rules = {p.stem: load_rule(str(p)) for p in sorted((ROOT / "rules").glob("*.yml"))}
    events = load_corpus()
    ref = reference(rules, events)
    print(f"corpus: {len(events)} events, {len(rules)} rules\n")
    failures = 0
    for engine in only:
        load, run, folder, ext = ENGINES[engine]
        print(f"== {engine}")
        load(events)
        for name in rules:
            query = (ROOT / "conversions" / folder / f"{name}.{ext}").read_text()
            try:
                got = run(query)
            except Exception as e:  # report and keep going: one bad query must not hide the rest
                failures += 1
                print(f"  ERROR  {name}: {e}")
                continue
            missed, extra = sorted(ref[name] - got), sorted(got - ref[name])
            if missed or extra:
                failures += 1
                print(f"  FAIL   {name}: missed={missed} extra={extra}")
            else:
                print(f"  ok     {name} ({len(got)} hits)")
        print()
    print("RESULT:", "all engines match the reference evaluator" if not failures
          else f"{failures} rule/engine mismatches")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
