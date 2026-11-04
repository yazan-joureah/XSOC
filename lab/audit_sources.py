r"""
audit_sources.py -- XSOC calibration, last step. Prints only; writes nothing.
(1) SECONDARY report: distinct alarming sources per day (added AFTER seeing the first results).
(2) AUDIT: behaviour profile of the 2018 sources that alarm near the chosen thresholds,
    next to the 2017 Tuesday attackers (development data). Wednesday-14 is never touched.
Needs calibrate.py in the same folder.

  python python\audit_sources.py --slice "data\slice\ports_21_22.csv" | Out-File -Encoding utf8 data\audit.txt
"""
import argparse
import numpy as np, pandas as pd
from calibrate import prep, episodes, addr_type, KEYS, CAL_2017, EXCLUDE_2018

def profile(rows):
    """simple behaviour numbers for the flows of ONE source."""
    rows = rows.sort_values("t")
    gaps = rows.groupby("day")["t"].diff().dropna()
    minutes = int((rows["t"] // 60).nunique())
    peak = max(p[3][120] for p in prep(rows, KEYS["src-dst-port"], [120]))
    per_target = rows.groupby(["dst_ip", "dst_port"]).size()
    return {"flows": len(rows), "days": rows["day"].nunique(), "targets": rows["dst_ip"].nunique(),
            "max_to_one_target": int(per_target.max()),
            "share_port22": round(float((rows["dst_port"] == 22).mean()), 2),
            "median_gap_s": round(float(gaps.median()), 1) if len(gaps) else None,
            "flows_per_active_min": round(len(rows) / max(minutes, 1), 1),
            "peak_in_120s": int(peak)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slice", required=True)
    ap.add_argument("--budget", type=int, default=5)
    ap.add_argument("--windows", type=int, nargs="+", default=[120, 900, 1800])
    ap.add_argument("--tgrid", type=int, nargs="+",
                    default=[2, 3, 4, 5, 8, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80, 90, 100, 150, 200])
    ap.add_argument("--audit-dataset", default="2018")
    ap.add_argument("--audit-points", nargs="+", default=["120:40", "900:60", "1800:60"])   # W:T (one grid step below chosen)
    ap.add_argument("--max-sources", type=int, default=15)
    a = ap.parse_args()
    tgrid = sorted(a.tgrid)

    df = pd.read_csv(a.slice, dtype={"dataset": str})
    df["t"] = (pd.to_datetime(df["timestamp"]) - pd.Timestamp("1970-01-01")).dt.total_seconds()
    benign = df[df["label"].str.upper() == "BENIGN"]
    days = {"2017": list(CAL_2017),
            "2018": sorted(set(df.loc[df["dataset"] == "2018", "day"]) - set(EXCLUDE_2018))}
    points = [tuple(int(x) for x in p.split(":")) for p in a.audit_points]
    wins = sorted(set(a.windows) | {w for w, _ in points})
    prepared = {g: {d: prep(benign[(benign["dataset"] == g) & (benign["day"] == d)], KEYS["src-dst-port"], wins)
                    for d in ds} for g, ds in days.items()}

    summary = {}
    for g, ds in days.items():
        table, prim, sec = {}, {}, {}
        for T in tgrid:
            table[T] = {}
            for W in a.windows:
                eps = {d: episodes(prepared[g][d], W, T) for d in ds}
                n_ep = [len(v) for v in eps.values()]
                n_cs = [len(set(v)) for v in eps.values()]
                table[T][f"W={W}s"] = f"{max(n_cs)}/{np.mean(n_cs):.1f}"
                if max(n_ep) <= a.budget: prim.setdefault(W, T)
                if max(n_cs) <= a.budget: sec.setdefault(W, T)
        summary[g] = (prim, sec)
        print(f"[SECONDARY | {g}] distinct alarming sources per day, worst/mean over {len(ds)} days (key src-dst-port)")
        print("  (added AFTER seeing the first results; the primary criterion stays: episodes)")
        print(pd.DataFrame(table).T.rename_axis("T").to_string(), "\n")

    print(f"[CALIBRATION SUMMARY v1] smallest grid T with worst day <= {a.budget}; key src-dst-port")
    for g, (prim, sec) in summary.items():
        for W in a.windows:
            print(f"  {g} | W={W}s | primary (episodes) T={prim.get(W, 'none')} | secondary (cases) T={sec.get(W, 'none')}")

    g = a.audit_dataset
    flagged = {}
    for W, T in points:
        for d in days[g]:
            for s in set(episodes(prepared[g][d], W, T)):
                flagged.setdefault(s, set()).add(f"{W}:{T}")
    cal = benign[(benign["dataset"] == g) & benign["day"].isin(days[g])]
    out = []
    ref = df[(df["dataset"] == "2017") & (df["day"] == "tuesday") & df["label"].str.contains("patator", case=False)]
    for lab, grp in ref.groupby("label"):
        out.append({"who": "REF 2017 tuesday " + lab, "type": addr_type(grp["src_ip"].iloc[0]),
                    "alarms_at": "-", **profile(grp)})
    order = sorted(flagged, key=lambda s: -int((cal["src_ip"] == s).sum()))
    for s in order[:a.max_sources]:
        out.append({"who": s, "type": addr_type(s), "alarms_at": " ".join(sorted(flagged[s])),
                    **profile(cal[cal["src_ip"] == s])})
    pd.set_option("display.width", 250)
    print(f"\n[AUDIT {g}] sources alarming at W:T = {a.audit_points} ({len(flagged)} source(s); showing {min(len(order), a.max_sources)})")
    print(pd.DataFrame(out).to_string(index=False))
    print("\nWednesday-14 was not used anywhere in this run.")

if __name__ == "__main__":
    main()