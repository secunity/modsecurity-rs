"""Prints medians from the result files written by run_library.sh /
run_nginx.sh."""
import collections
import re
import statistics as st
import sys


def library(path):
    rows = collections.defaultdict(list)
    for line in open(path):
        if line.startswith("DONE"):
            continue
        sc, lib, rest = line.split(" ", 2)
        rows[(sc, lib)].append({k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", rest)})
    for sc in sorted({k[0] for k in rows}):
        base = st.median(x["tx_per_s"] for x in rows[(sc, "cpp")])
        print(sc)
        for lib in ("cpp", "rs"):
            r = rows[(sc, lib)]
            med = {k: st.median(x[k] for x in r) for k in r[0]}
            print(f"  {lib:4} tx/s={med['tx_per_s']:8.1f} ({med['tx_per_s'] / base:.2f}x)  p50={med['p50_us']:7.1f}us"
                  f"  p99={med['p99_us']:8.1f}us  load={med['load_ms']:5.1f}ms  rss={med['maxrss_mb']:.1f}MB")


def ms(x):
    m = re.match(r"([\d.]+)(us|ms|s)", x)
    v = float(m.group(1))
    return {"us": v / 1000, "ms": v, "s": v * 1000}[m.group(2)]


def nginx(path):
    rows, rss, cfg = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
    for line in open(path):
        d = dict(re.findall(r"(\w+)=(\S+)", line))
        if "config_test_ms" in d:
            cfg[d["variant"]].append(int(d["config_test_ms"]))
        elif "worker_rss_kb" in d:
            rss[d["variant"]].append(int(d["worker_rss_kb"]))
        elif "scenario" in d:
            rows[(d["scenario"], d["variant"])].append((float(d["rps"]), ms(d["p50"]), ms(d["p99"])))
    variants = [v for v in ("none", "cpp", "rustlib", "rustconn") if v in rss]
    for s in ("get", "attack", "post"):
        base = st.median(r[0] for r in rows[(s, "cpp")])
        print(s)
        for v in variants:
            r = rows[(s, v)]
            rps = st.median(x[0] for x in r)
            print(f"  {v:9} rps={rps:9.0f} ({rps / base:.2f}x)  p50={st.median(x[1] for x in r):7.2f}ms"
                  f"  p99={st.median(x[2] for x in r):7.2f}ms")
    for v in variants:
        print(f"{v:9} worker_rss={st.median(rss[v]) / 1024:.0f}MB  nginx_-t={st.median(cfg[v])}ms")


{"library": library, "nginx": nginx}[sys.argv[1]](sys.argv[2])
