"""
make_slice.py -- XSOC: keep only the rows whose destination port is 21 or 22, from FULL files (no row limit),
and write ONE small CSV for the calibration step. Reads in chunks. Never overwrites an existing file.

  python python\make_slice.py --dataset 2017 --files "data\raw\<2017 folder>\*.csv" --out "data\slice\ports_21_22.csv"
  python python\make_slice.py --dataset 2018 --files "data\raw\CSECICIDS2018_improved\*.csv" --out "data\slice\ports_21_22.csv" --append
"""
import argparse, glob, os, sys, time
import pandas as pd

ALIASES = {"src_ip": ["src ip", "source ip"],
           "dst_ip": ["dst ip", "destination ip"],
           "dst_port": ["dst port", "destination port"],
           "timestamp": ["timestamp"],
           "label": ["label"]}
PORTS = {21, 22}

def norm(c): return " ".join(str(c).split()).lower()

def find_cols(header):
    """role -> real column name; stops with a clear message if a role is missing."""
    mp = {norm(c): c for c in header}
    found, missing = {}, []
    for role, names in ALIASES.items():
        hit = next((mp[n] for n in names if n in mp), None)
        if hit is None: missing.append(role)
        else: found[role] = hit
    if missing: sys.exit(f"missing columns for roles {missing}.\nHeader seen: {list(header)[:15]} ...")
    return found

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)            # e.g. 2017 or 2018 (stored as a column)
    ap.add_argument("--files", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")       # add to an existing slice file (second dataset)
    ap.add_argument("--chunk-rows", type=int, default=500_000)
    ap.add_argument("--dayfirst", action="store_true")     # add only if timestamps fail to parse
    a = ap.parse_args()

    files = sorted({f for pat in a.files for f in glob.glob(pat)})
    if not files: sys.exit(f"no file matches {a.files}")
    exists = os.path.exists(a.out)
    if exists and not a.append:
        sys.exit(f"{a.out} already exists: use --append to add to it, or choose another name")
    folder = os.path.dirname(a.out)
    if folder: os.makedirs(folder, exist_ok=True)

    write_header = not exists
    summary, bad_ts = {}, 0                                 # (day, label) -> rows
    t0 = time.time()

    for f in files:
        day = os.path.splitext(os.path.basename(f))[0]
        cols = find_cols(pd.read_csv(f, nrows=0).columns)
        read = kept = 0
        for ch in pd.read_csv(f, usecols=list(cols.values()), chunksize=a.chunk_rows, low_memory=False):
            read += len(ch)
            port = pd.to_numeric(ch[cols["dst_port"]], errors="coerce")
            sl = ch.loc[port.isin(PORTS)]
            if sl.empty: continue
            out = pd.DataFrame({
                "dataset": a.dataset,
                "day": day,
                "src_ip": sl[cols["src_ip"]].astype(str).str.strip(),
                "dst_ip": sl[cols["dst_ip"]].astype(str).str.strip(),
                "dst_port": port.loc[sl.index].astype(int),
                "timestamp": pd.to_datetime(sl[cols["timestamp"]], errors="coerce", dayfirst=a.dayfirst),
                "label": sl[cols["label"]].astype(str).str.strip()})
            bad_ts += int(out["timestamp"].isna().sum())
            out = out.dropna(subset=["timestamp"])
            out["timestamp"] = out["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.%f")
            out.to_csv(a.out, mode="a", header=write_header, index=False)
            write_header = False
            kept += len(out)
            for k, v in out["label"].value_counts().items():
                summary[(day, k)] = summary.get((day, k), 0) + int(v)
        print(f"  done {day}: read {read:,} | kept {kept:,} ({time.time()-t0:.0f}s)", flush=True)

    print("\nrows written per (day, label):")
    for (day, lab), n in sorted(summary.items()):
        print(f"  {day} | {lab}: {n:,}")
    print(f"\nrows with unparsable timestamp (dropped): {bad_ts:,}")
    print(f"written to {a.out} ({os.path.getsize(a.out)/1e6:.1f} MB), total {time.time()-t0:.0f}s")

if __name__ == "__main__":
    main()