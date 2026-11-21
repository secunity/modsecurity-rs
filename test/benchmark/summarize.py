"""Prints the results written by run_library.sh / run_nginx.sh: per scenario
and variant, the best and the median of the rounds, and the ratio of the
medians to the first variant."""
import collections
import re
import statistics as st
import sys


def library(path):
    rows = collections.defaultdict(list)
    order = []
    for line in open(path):
        if line.startswith("DONE"):
            continue
        sc, lib, rest = line.split(" ", 2)
        if lib not in order:
            order.append(lib)
        rows[(sc, lib)].append({k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", rest)})
    for sc in ("upstream", "corpus_pl1", "corpus_pl4"):
        if not any(k[0] == sc for k in rows):
            continue
        base = st.median(x["tx_per_s"] for x in rows[(sc, order[0])])
        print(sc)
        for lib in order:
            r = rows[(sc, lib)]
            med = {k: st.median(x[k] for x in r) for k in r[0]}
            best = max(x["tx_per_s"] for x in r)
            print(f"  {lib:10} tx/s best={best:8.1f} median={med['tx_per_s']:8.1f} ({med['tx_per_s'] / base:.3f}x)"
                  f"  p50={med['p50_us']:7.1f}us  p99={med['p99_us']:8.1f}us  load={med['load_ms']:5.1f}ms"
                  f"  rss={med['maxrss_mb']:.1f}MB  rounds={len(r)}")


def ms(x):
    m = re.match(r"([\d.]+)(us|ms|s)", x)
    v = float(m.group(1))
    return {"us": v / 1000, "ms": v, "s": v * 1000}[m.group(2)]


def nginx(path):
    rows, rss, cfg = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
    bad = []
    order = []
    for line in open(path):
        d = dict(re.findall(r"(\w+)=(\S+)", line))
        v = d.get("variant")
        if v and v not in order:
            order.append(v)
        if "config_test_ms" in d:
            cfg[v].append(int(d["config_test_ms"]))
        elif "worker_rss_kb" in d:
            rss[v].append(int(d["worker_rss_kb"]))
        elif "scenario" in d:
            rows[(d["scenario"], v)].append((float(d["rps"]), ms(d["p50"]), ms(d["p99"])))
            if d.get("unexpected", "0") != "0":
                bad.append(line.strip())
    modules = [v for v in order if v != "none"]
    base_v = modules[0] if modules else order[0]
    for s in ("get", "attack", "post"):
        base = st.median(r[0] for r in rows[(s, base_v)])
        print(s)
        for v in order:
            r = rows[(s, v)]
            rps = [x[0] for x in r]
            print(f"  {v:9} rps best={max(rps):9.0f} median={st.median(rps):9.0f} ({st.median(rps) / base:.3f}x)"
                  f"  p50={st.median(x[1] for x in r):7.2f}ms  p99={st.median(x[2] for x in r):7.2f}ms")
    for v in order:
        print(f"{v:9} worker_rss={st.median(rss[v]) / 1024:.0f}MB  nginx_-t={st.median(cfg[v])}ms")
    if bad:
        print("UNEXPECTED STATUS CODES (these runs do not measure what they should):")
        for line in bad:
            print("  " + line)
        sys.exit(1)


{"library": library, "nginx": nginx}[sys.argv[1]](sys.argv[2])
