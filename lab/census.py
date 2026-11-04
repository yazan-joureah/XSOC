"""
census.py -- XSOC data census (read-only).
Question it answers: how much evidence do we really have to calibrate and test a brute-force rule?
Prints tables only; writes nothing. Reads big files in chunks (constant memory).

  python census.py --name monday_2017 --files "data/raw/<file>.csv" [--flow-list profiles/flow_v1.txt] [--max-rows-per-file 200000]
"""
import argparse, glob, os, re, sys, time
import numpy as np, pandas as pd

ALIASES = {"src": ["src ip", "source ip"],
           "dport": ["dst port", "destination port"],
           "ts": ["timestamp"],
           "label": ["label"]}
AUTH_PORTS = {21, 22}

def norm(c): return " ".join(str(c).split()).lower()

def read_list(path):
    return [l.strip() for l in open(path, encoding="utf-8") if l.strip() and not l.lstrip().startswith("#")]

def find_cols(header):
    """role -> real column name. Stops with a clear message if a role is missing."""
    mp = {norm(c): c for c in header}
    found, missing = {}, []
    for role, names in ALIASES.items():
        hit = next((mp[n] for n in names if n in mp), None)
        if hit is None: missing.append(role)
        else: found[role] = hit
    if missing: sys.exit(f"missing columns for roles {missing}.\nHeader seen: {list(header)[:15]} ...")
    return found, mp

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--files", nargs="+", required=True)
    ap.add_argument("--flow-list")                       # flow_v1 column names, one per line (needed only for the duplicates table)
    ap.add_argument("--keep-labels", default="benign|patator|brute")
    ap.add_argument("--chunk-rows", type=int, default=400_000)
    ap.add_argument("--max-rows-per-file", type=int, default=0)   # 0 = all rows; use a small number for a test run
    ap.add_argument("--dayfirst", action="store_true")            # add if many timestamps fail to parse (e.g. 14/02/2018)
    a = ap.parse_args()

    t0 = time.time()
    files = sorted({f for pat in a.files for f in glob.glob(pat)})
    if not files: sys.exit(f"no file matches {a.files}")
    keep_re = re.compile(a.keep_labels, re.IGNORECASE)
    flow_names = read_list(a.flow_list) if a.flow_list else []

    label_counts, hashes = {}, {}
    flows_per_src = None                                  # Series indexed by (group, source)
    ts_min, ts_max = {}, {}
    ts_total = ts_bad = 0

    for f in files:
        header = pd.read_csv(f, nrows=0).columns
        cols, mp = find_cols(header)
        fcols = [mp[norm(n)] for n in flow_names if norm(n) in mp]
        lost = [n for n in flow_names if norm(n) not in mp]
        if lost: print(f"WARNING {os.path.basename(f)}: {len(lost)} flow columns missing: {lost[:4]}")
        use = list(dict.fromkeys([cols["src"], cols["dport"], cols["ts"], cols["label"]] + fcols))
        seen = 0
        for ch in pd.read_csv(f, usecols=use, chunksize=a.chunk_rows, low_memory=False):
            if a.max_rows_per_file and seen + len(ch) > a.max_rows_per_file:
                ch = ch.iloc[: a.max_rows_per_file - seen]
            seen += len(ch)

            lab = ch[cols["label"]].astype(str).str.strip()
            for k, v in lab.value_counts().items(): label_counts[k] = label_counts.get(k, 0) + int(v)
            m = lab.str.contains(keep_re)
            if m.any():
                d, lab_k = ch.loc[m], lab[m]
                port = pd.to_numeric(d[cols["dport"]], errors="coerce")
                pg = pd.Series(np.where(port.isin(AUTH_PORTS), "21/22", "other"), index=d.index)
                grp = lab_k + " [port " + pg + "]"
                src = d[cols["src"]].astype(str).str.strip()

                part = pd.DataFrame({"g": grp, "s": src}).groupby(["g", "s"]).size()
                flows_per_src = part if flows_per_src is None else flows_per_src.add(part, fill_value=0)

                ts = pd.to_datetime(d[cols["ts"]], errors="coerce", dayfirst=a.dayfirst)
                ts_total += len(ts); ts_bad += int(ts.isna().sum())
                mm = pd.DataFrame({"g": grp, "t": ts}).dropna().groupby("g")["t"].agg(["min", "max"])
                for g, r in mm.iterrows():
                    ts_min[g] = min(ts_min.get(g, r["min"]), r["min"])
                    ts_max[g] = max(ts_max.get(g, r["max"]), r["max"])

                if fcols:                                 # duplicates: attack labels only
                    am = ~lab_k.str.lower().str.startswith("benign")
                    if am.any():
                        feat = d.loc[am, fcols].apply(pd.to_numeric, errors="coerce").astype("float64")
                        h = pd.util.hash_pandas_object(feat, index=False).to_numpy()
                        la = lab_k[am]
                        for k in la.unique(): hashes.setdefault(k, []).append(h[(la == k).to_numpy()])
            if a.max_rows_per_file and seen >= a.max_rows_per_file: break
        print(f"  done {os.path.basename(f)}  ({time.time()-t0:.0f}s)", flush=True)

    pd.set_option("display.width", 250)
    print(f"\n===== {a.name}: {len(files)} file(s) =====")
    print("\n[1] ALL labels (* = included in the census)")
    for k, v in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"  {'*' if keep_re.search(k) else ' '} {k}: {v:,}")
    if flows_per_src is None: sys.exit("no row matched --keep-labels")

    rows = []
    for g, s in flows_per_src.groupby(level=0):
        n = s.to_numpy()
        rows.append({"group": g, "flows": int(n.sum()), "sources": len(n), "per_src_min": int(n.min()),
                     "per_src_median": int(np.median(n)), "per_src_max": int(n.max()),
                     "first": ts_min.get(g, "?"), "last": ts_max.get(g, "?")})
    print("\n[2] Census per group (label + destination-port class)")
    print(pd.DataFrame(rows).sort_values("group").to_string(index=False))

    if hashes:
        print("\n[3] Attack labels: raw rows vs unique feature vectors (flow_v1 columns)")
        for k, v in sorted(hashes.items()):
            h = np.concatenate(v)
            print(f"  {k}: rows {len(h):,} | unique vectors {len(np.unique(h)):,}")
    elif flow_names:
        print("\n[3] no attack rows in these files, so no duplicates table")
    else:
        print("\n[3] skipped (no --flow-list given)")

    print(f"\ntimestamps that failed to parse: {ts_bad:,} of {ts_total:,}")
    print("note: a source = one Src IP string; several machines behind one NAT address count as one.")
    print(f"{time.time()-t0:.0f}s")

if __name__ == "__main__":
    main()