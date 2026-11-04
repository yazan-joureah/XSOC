r"""
measure.py -- XSOC: attack measurement at the FROZEN operating points (CALIBRATION SUMMARY v1, 2026-10-29).
Prints only; writes nothing. The rule is label-blind: it sees ALL flows of the day, labels are used only to read the result.

  dev  : Tuesday 2017         python python\measure.py --slice "data\slice\ports_21_22.csv" --stage dev
  test : Wednesday-14 2018    python python\measure.py --slice "data\slice\ports_21_22.csv" --stage test --confirm-test   (run ONCE)
Needs calibrate.py in the same folder (reuses prep/episodes for the port-scan check).
"""
import argparse, sys
import numpy as np, pandas as pd
from calibrate import prep, episodes, KEYS

FROZEN = {"2017": {"primary": [(120, 3), (900, 15), (1800, 20)], "secondary": []},
          "2018": {"primary": [(120, 45), (900, 70), (1800, 70)], "secondary": [(120, 10), (900, 20), (1800, 20)]}}
STAGES = {"dev": ("2017", "tuesday"), "test": ("2018", "Wednesday-14-02-2018")}
CRITERIA = """Frozen 2026-10-29 (written after calibration, before any attack measurement; rates seen earlier are disclosed).
FIELD 1: PASS if the main attack episode alarms at ALL primary points of this dataset.
FIELD 2: PASS if its first alarm comes before the attacker sent 100 flows to the same target (flow index < 100).
REPORT ONLY (no pass/fail): Attempted, Portscan, secondary points. Unit = flow (a flow may hold several attempts)."""

def classify(labels):
    main, att, scan = [], [], []
    for l in sorted(set(labels)):
        low = l.lower()
        if low == "benign": continue
        (att if "attempted" in low else scan if "portscan" in low else main).append(l)
    return main, att, scan

def key_tables(day_df, windows):
    """label-blind: per key (src, dst, port): sorted times + flows inside the window ending at each flow."""
    tabs = []
    for (s, d, p), g in day_df.groupby(["src_ip", "dst_ip", "dst_port"], sort=False):
        g = g.sort_values("t")
        t = g["t"].to_numpy()
        c = {W: np.searchsorted(t, t, side="right") - np.searchsorted(t, t - W, side="right") for W in windows}
        tabs.append({"key": (s, d, int(p)), "t": t, "c": c, "labels": g["label"].to_numpy()})
    return tabs

def first_alarm(tab, W, T):
    """(flow index of the first alarm, seconds since the key's first flow) or (None, None)."""
    hit = np.flatnonzero(tab["c"][W] >= T)
    if not len(hit): return None, None
    return int(hit[0]) + 1, float(tab["t"][hit[0]] - tab["t"][0])

def report_point(tabs, main, att, W, T, outcomes=None):
    for G in main:
        ks = [x for x in tabs if G in x["labels"]]
        ep = max(ks, key=lambda x: int((x["labels"] == G).sum()))      # main episode = key with most flows of this label
        idx, sec = first_alarm(ep, W, T)
        head = f"  MAIN {G}: key {ep['key']} | {int((ep['labels'] == G).sum()):,} {G} flows, {len(ep['t']):,} flows in key"
        extra = sorted(set(ep["labels"]) - {G})
        if extra: head += f" (also: {', '.join(extra)})"
        if len(ks) > 1: head += f" | {len(ks)} keys carry this label, the largest is judged"
        print(head)
        print("      NO ALARM" if idx is None else f"      first alarm at flow #{idx} of the key ({sec:.0f}s after its first flow)")
        if outcomes is not None: outcomes.append((G, W, T, idx is not None, idx))
    for G in att:
        ks = [x for x in tabs if G in x["labels"]]
        idxs = [i for i in (first_alarm(x, W, T)[0] for x in ks) if i is not None]
        line = (f"  ATTEMPTED {G}: {sum(int((x['labels'] == G).sum()) for x in ks):,} flows in {len(ks):,} key(s); "
                f"keys with an alarm: {len(idxs)}")
        if idxs: line += f" (first-alarm flow # min/median/max = {min(idxs)}/{int(np.median(idxs))}/{max(idxs)})"
        if any(set(x["labels"]) & set(main) for x in ks): line += " | NOTE: shares keys with main-attack flows"
        print(line)

def main_():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slice", required=True)
    ap.add_argument("--stage", choices=["dev", "test"], required=True)
    ap.add_argument("--confirm-test", action="store_true")
    a = ap.parse_args()
    if a.stage == "test" and not a.confirm_test:
        sys.exit("test stage = Wednesday-14, to be run ONCE. Add --confirm-test to run it.")
    ds, day = STAGES[a.stage]
    pts = FROZEN[ds]

    df = pd.read_csv(a.slice, dtype={"dataset": str})
    df["t"] = (pd.to_datetime(df["timestamp"]) - pd.Timestamp("1970-01-01")).dt.total_seconds()
    day_df = df[(df["dataset"] == ds) & (df["day"] == day)]
    if day_df.empty: sys.exit(f"no rows for {ds}/{day}: check the day name")
    main, att, scan = classify(day_df["label"].unique())
    if not main: sys.exit(f"no main attack label in {day}")

    print(CRITERIA)
    print(f"\nStage {a.stage}: {ds} / {day}: {len(day_df):,} flows")
    print(f"labels -> main: {main} | attempted: {att} | port-scan: {scan}")
    windows = sorted({W for W, _ in pts["primary"] + pts["secondary"]})
    tabs = key_tables(day_df, windows)

    outcomes = []
    for W, T in pts["primary"]:
        print(f"\n--- PRIMARY W={W}s T={T} ---")
        report_point(tabs, main, att, W, T, outcomes)
    for W, T in pts["secondary"]:
        print(f"\n--- SECONDARY (report only) W={W}s T={T} ---")
        report_point(tabs, main, att, W, T)

    f1 = [(G, W, T) for G, W, T, ok, idx in outcomes if not ok]
    f2 = [(G, W, T, idx) for G, W, T, ok, idx in outcomes if (not ok) or idx >= 100]
    print("\n[VERDICT, primary points only]")
    print(f"  FIELD 1 (detection): {'PASS' if not f1 else 'FAIL ' + str(f1)}")
    print(f"  FIELD 2 (alarm before flow #100): {'PASS' if not f2 else 'FAIL ' + str(f2)}")
    print("  Overall acceptance needs BOTH stages (dev and test) to pass.")

    scans = df[(df["dataset"] == ds) & df["label"].str.contains("portscan", case=False)]
    print("\n[PORT-SCAN CHECK] report only; scan flows alone, same method as calibrate.py (episodes per day)")
    if scans.empty: print("  no port-scan rows in this dataset")
    for tag, plist in (("primary", pts["primary"]), ("secondary", pts["secondary"])):
        for W, T in plist:
            out = [f"{d}: {len(episodes(prep(scans[scans['day'] == d], KEYS['src-dst-port'], [W]), W, T))}"
                   for d in sorted(scans["day"].unique())]
            print(f"  [{tag}] W={W}s T={T} -> " + "; ".join(out))

if __name__ == "__main__":
    main_()