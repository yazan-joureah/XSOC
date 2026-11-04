r"""
calibrate.py -- XSOC: calibrate the repeat threshold T for each window W on BENIGN rows only,
then report false-alarm episodes per capture day, and WHO raises them. Prints tables only; writes nothing.
Alarm convention: a key raises an alarm when it has >= T flows inside a window of W seconds.

  python python\calibrate.py --slice "data\slice\ports_21_22.csv"
"""
import argparse, ipaddress, sys
import numpy as np, pandas as pd

KEYS = {"src-dst-port": ["src_ip", "dst_ip", "dst_port"],   # primary key (as in the rule card)
        "src-port": ["src_ip", "dst_port"]}                  # sensitivity: ignores the target
CAL_2017 = ["monday", "wednesday", "thursday", "friday"]     # tuesday = development, not here
EXCLUDE_2018 = ["Wednesday-14-02-2018"]                      # unseen test day, never used for calibration

def prep(df, key_cols, windows):
    """per key: sorted times + number of flows inside the window ending at each flow."""
    out = []
    for k, g in df.groupby(key_cols, sort=False):
        t = np.sort(g["t"].to_numpy())
        c = {W: np.searchsorted(t, t, side="right") - np.searchsorted(t, t - W, side="right") for W in windows}
        out.append((k[0], t, c, {W: int(c[W].max()) for W in windows}))   # k[0] = source IP
    return out

def episodes(prepared, W, T):
    """alarm episodes (one source entry each). Alarms closer than W seconds merge into one episode."""
    srcs = []
    for src, t, c, peak in prepared:
        if peak[W] < T: continue
        at = t[c[W] >= T]
        srcs.extend([src] * (1 + int((np.diff(at) >= W).sum())))
    return srcs

def addr_type(ip):
    try: return "private" if ipaddress.ip_address(ip).is_private else "public"
    except ValueError: return "unparsed"

def show_sources(results, flows_by, g, kn, W, T, note=""):
    """top sources behind the alarms at one operating point: episodes, days, flows."""
    per_day = results[(g, kn, W, T)]
    agg = {}                                                  # source -> [episodes, days, flows]
    for d, srcs in per_day.items():
        for s in set(srcs):
            e = agg.setdefault(s, [0, 0, 0])
            e[0] += srcs.count(s); e[1] += 1; e[2] += int(flows_by.get((g, d, s), 0))
    total = sum(v[0] for v in agg.values())
    print(f"  {g} | {kn} | W={W}s | T={T}{note}: {total} episodes from {len(agg)} source(s)")
    for s, (e, nd, nf) in sorted(agg.items(), key=lambda x: -x[1][0])[:8]:
        print(f"      {s} [{addr_type(s)}]: {e} episodes on {nd} day(s), {nf:,} flows on those days")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slice", required=True)
    ap.add_argument("--budget", type=int, default=5)                     # max false-alarm episodes on the worst day
    ap.add_argument("--windows", type=int, nargs="+", default=[120, 900, 1800])
    ap.add_argument("--tgrid", type=int, nargs="+", default=[2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 50, 100])
    ap.add_argument("--cal-2017", nargs="+", default=CAL_2017)
    ap.add_argument("--exclude-2018", nargs="+", default=EXCLUDE_2018)
    a = ap.parse_args()

    df = pd.read_csv(a.slice, dtype={"dataset": str})
    df["t"] = (pd.to_datetime(df["timestamp"]) - pd.Timestamp("1970-01-01")).dt.total_seconds()
    benign = df[df["label"].str.upper() == "BENIGN"]
    flows_by = benign.groupby(["dataset", "day", "src_ip"]).size().to_dict()
    days18 = sorted(set(df.loc[df["dataset"] == "2018", "day"]) - set(a.exclude_2018))
    groups = {"2017": list(a.cal_2017), "2018": days18}

    print("Calibration days (BENIGN only):")
    for g, days in groups.items():
        for d in days:
            b = benign[(benign["dataset"] == g) & (benign["day"] == d)]
            if b.empty: sys.exit(f"no BENIGN rows for {g}/{d}: check the day names")
            print(f"  {g} | {d}: {len(b):,} flows, {b['src_ip'].nunique():,} sources")
    print(f"Excluded on purpose: {a.exclude_2018} (2018 test) and tuesday (2017 development)")

    results = {}                                   # (dataset, key, W, T) -> {day: [source per episode]}
    for g, days in groups.items():
        for kn, kc in KEYS.items():
            prepared = {d: prep(benign[(benign["dataset"] == g) & (benign["day"] == d)], kc, a.windows) for d in days}
            for W in a.windows:
                for T in a.tgrid:
                    results[(g, kn, W, T)] = {d: episodes(p, W, T) for d, p in prepared.items()}

    for g in groups:
        for kn in KEYS:
            rows = {}
            for T in a.tgrid:
                rows[T] = {}
                for W in a.windows:
                    n = [len(v) for v in results[(g, kn, W, T)].values()]
                    rows[T][f"W={W}s"] = f"{max(n)}/{np.mean(n):.1f}"
            print(f"\n[{g} | key {kn}] false-alarm episodes per day, worst/mean over {len(groups[g])} days")
            print(pd.DataFrame(rows).T.rename_axis("T").to_string())

    print(f"\n[Operating points] smallest T whose worst-day episodes <= {a.budget}")
    chosen = {}
    for g in groups:
        for kn in KEYS:
            for W in a.windows:
                worst = {T: max(len(v) for v in results[(g, kn, W, T)].values()) for T in a.tgrid}
                ok = [T for T in a.tgrid if worst[T] <= a.budget]
                if not ok:
                    print(f"  {g} | {kn} | W={W}s: no T in the grid meets the budget"); continue
                T = min(ok); chosen[(g, kn, W)] = T
                per_day = results[(g, kn, W, T)]
                counts = {d: len(v) for d, v in per_day.items()}
                wd = max(counts, key=counts.get)
                notes = ""
                if T == min(a.tgrid): notes += " [grid lower bound reached]"
                if any(worst[x] > a.budget for x in a.tgrid if x > T): notes += " [WARNING: a larger T breaks the budget again]"
                print(f"  {g} | {kn} | W={W}s: T={T} | per-day {list(counts.values())} | sources on worst day {len(set(per_day[wd]))}{notes}")

    print("\n[Alarm sources] who raises the false alarms (top 8 per point)")
    for g in groups:
        for kn in KEYS:
            for W in a.windows:
                T = chosen.get((g, kn, W))
                if T is None:
                    show_sources(results, flows_by, g, kn, W, max(a.tgrid), " (largest T, budget NOT met)")
                    continue
                show_sources(results, flows_by, g, kn, W, T, " (chosen)")
                lower = [x for x in a.tgrid if x < T]
                if lower: show_sources(results, flows_by, g, kn, W, max(lower), " (one grid step below)")

    scans = df[df["label"].str.contains("portscan", case=False)]
    print("\n[Hard negatives] port-scan flows at the chosen T: episodes per day")
    for (g, kn, W), T in chosen.items():
        out = []
        for d in sorted(set(scans.loc[scans["dataset"] == g, "day"])):
            s = scans[(scans["dataset"] == g) & (scans["day"] == d)]
            out.append(f"{d}: {len(episodes(prep(s, KEYS[kn], [W]), W, T))}")
        if out: print(f"  {g} | {kn} | W={W}s | T={T} -> " + "; ".join(out))

if __name__ == "__main__":
    main()