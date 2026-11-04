# flow_v1 - record of how the frozen flow-metric list was chosen

Status: **FROZEN 2026-10-23** by the pre-declared rules V1 / E1 / X1 / P1 / C1. List: `flow_v1.txt` (52 columns).
Telemetry source: CICFlowMeter flow records (the "improved" CIC-IDS2017 and CSE-CIC-IDS2018 exports). Another source (for example Wazuh sshd log events) needs its own list.

## 1. Result

flow_v1 = the 68-column candidate pool minus 16 columns excluded by `column_shift` (rule X1). No shortening was justified: the three shortened lists (19, 27 and 34 columns) each failed the held-out check against the pool minus the exclusions, so the rule froze the last fallback, the 52-column list.

Be careful how you read it: 25 of the 52 columns have a mean importance at or below the noise floor (0.001) and 18 were never in the top-15 of any scenario. They are in the list because the rule found no justified way to remove them, not because they were shown to matter. 34 of the 52 come only from the diagnostic list; 18 are also in the 29-column main list (11 of the 29 were removed by X1).

## 2. Data and protocol

- 14 files: CICIDS2017 improved (Tuesday-Friday; Monday = reference baseline, not training) and CSE-CIC-IDS2018 improved (10 files). Families: BruteForce, DoS, PortScan, WebAttack, Botnet (Infiltration excluded: too small).
- 4,837,694 unique vectors after per-file+label de-duplication (weights keep the original row counts). Benign capped at 200,000 unique vectors per file; attack families kept whole, with a safety cap of 500,000 that applied only to DoS in 2018 Friday-16 and Wednesday-21.
- Leave-one-dataset-out: fold "2017" = train on 2018, test on 2017; fold "2018" = the reverse.
- Random forest, 100 trees, at most 150,000 class-balanced training rows, 5 seeds (base seed 42). Column importance = ROC-AUC lost when the column is shuffled (10 permutation repeats; stability measured over 3 seeds). A run is *usable* for ranking if its AUC >= 0.70.
- 8 scenarios: list (main 29 / diagnostic 68) x with/without Dst Port+Protocol x with/without Attempted rows.
- scikit-learn 1.9.1, pandas 3.0.5, numpy 2.5.3. The RF is an offline tool for choosing columns, not a detector; Prolog stays the judge.

## 3. Rules (fixed before the results)

| rule | what it says |
|---|---|
| V1 | A scenario ranking uses only usable runs. If a fold has no usable run in any scenario, nothing is frozen (inconclusive). |
| E1 | A column enters a candidate list if a unit containing it (twin columns travel together) is in the top-k of at least a share of the scenarios where it is a candidate. Chain of cells: (k=10, 50%), (15, 50%), (15, 25%). Ranking inside a scenario = family-balanced AUC importance, above the noise floor 0.001. |
| X1 | Exclusion without RF: the sign of the attack/benign separation flips between the datasets in any family, or the attack value is constant (mode share >= 0.9 in both datasets) AND the column is a TCP-stack field (init window, segment size, ...). Thresholds 0.3 / 0.3 / 0.9, re-evaluated on a 27-combination grid. |
| P1 | Dst Port / Protocol are kept only if AUC(with) - AUC(without) > 1 standard error in both folds. |
| C1 | Each candidate cell is run as its own column list in the same scenarios; per scenario and fold, the paired-by-seed AUC difference (list - baseline) must be >= -1 SE. First passing cell is frozen; if the last cell fails, the fallback (pool minus X1 exclusions) is frozen. |

Changes made after some results were visible (disclosed):

1. The ranking was made family-balanced (each family weighs the same) after the load step and before any pooled result, because DoS is about 2/3 (2017) to 5/6 (2018) of the attack vectors.
2. A sensitivity section for the usable-run threshold was added before the select step ran on the real data.
3. **C1 baseline.** It was first "the full list" (the 29-column main list for the `main-*` scenarios, the 68-column diagnostic list for the `diag-*` ones). After seeing the select report and **before any check result**, it was changed to "the pool minus the X1 exclusions" (the 52-column list), because the full lists contain the columns X1 removes and would penalise every shorter list for X1's decision. Cell 0 was also compared with the full lists for information (same verdict, section 5.4). Cells 1 and 2 were run only against the new baseline. Not run against the 29-column main list; from the mean AUCs alone (no SE) their fold-2018 differences would be -0.111 / -0.064 (cell 1) and -0.058 / -0.104 (cell 2, att / noatt), so that comparison would not have helped them either.

## 4. What the pooled run showed

- Fold 2017 (train 2018): AUC 0.97-0.99 in all 8 scenarios. Fold 2018 (train 2017): AUC 0.55-0.77. V1 passes: usable runs per fold, summed over scenarios: 2017 = 40 of 40, 2018 = 11 of 40 (all in scenarios that keep Attempted rows).
- Why fold 2018 is low (scenario main-pp-noatt, recall at the 50% cutoff, mean of 5 seeds): DDoS-HOIC (31% of the fold's attack vectors), Hulk (31%), DDoS-LOIC-HTTP (18%), SSH brute force (6%) and others, about 87% of vectors in total, are detected at 0-3%. Detected: Botnet-Ares 81% (one seed collapsed to 5%), NMAP 84%, Slowloris 98%, WebAttack-XSS 97%. Hulk exists in both datasets and fails in both directions. So the pooled AUC of fold 2018 is dominated by DoS floods that do not transfer.
- In fold 2017 the AUC is 0.97-0.99 but only 9-46% of attacks are detected at the 50% cutoff: the columns rank attacks well, the cutoff does not transfer. In that direction too, Hulk (39% of the fold's vectors) and DDoS (23%) are detected at 0-4%, and FTP brute force at 6%.
- Price of X1 (mean AUC, 5 seeds, scenario names as in the check; reference -> the 52-column list):

| reference list | 2017 att | 2017 noatt | 2018 att | 2018 noatt |
|---|---|---|---|---|
| 68-column diagnostic list (X1 is the only difference) | 0.9859 -> 0.9828 | 0.9857 -> 0.9781 | 0.6936 -> 0.6294 | 0.6429 -> 0.5879 |
| 29-column main list (also has Dst Port; different column set) | 0.9852 -> 0.9828 | 0.9877 -> 0.9781 | 0.7333 -> 0.6294 | 0.6455 -> 0.5879 |

  Removing the 16 columns costs 0.003-0.008 in fold 2017 and 0.055-0.064 in fold 2018 (against the 68-column list). Fold 2018 was already weak with them (0.64-0.73), and with the 52-column list single seeds in noatt/2018 are at 0.47-0.55 AUC.

## 5. Selection details

### 5.1 X1 exclusions (16 columns)

| column | why | families | threshold combos that agree (of 27) |
|---|---|---|---|
| FWD Init Win Bytes, Fwd Seg Size Min | attack-constant + TCP-stack field | Botnet, BruteForce, WebAttack | 27 |
| Bwd Init Win Bytes | attack-constant + TCP-stack field | Botnet, PortScan | 27 |
| Flow Packets/s, Fwd Packets/s, Bwd Packets/s, Flow Bytes/s, Flow IAT Mean, Flow IAT Std, Fwd IAT Mean, RST Flag Count | sign flips | BruteForce | 27 |
| Flow IAT Max, Bwd IAT Mean | sign flips | BruteForce | 18 |
| Dst Port | sign flips | DoS, WebAttack | 18 |
| Down/Up Ratio, Fwd IAT Std | sign flips | Botnet | 18 |

The five columns at 18/27 depend on the conventional thresholds.

### 5.2 P1 (Dst Port / Protocol)

Fold 2017: +0.0066 +/- 0.0013 (20 pairs) PASS; fold 2018: +0.0173 +/- 0.0089 (20 pairs) PASS. Decision: keep if they pass E1. Dst Port passed E1 in every cell (top-10 in 4 of 4 scenarios, mean importance 0.070 against 0.011 for the top column of the cell-0 list) but is excluded by X1 (sign flips in DoS and WebAttack, 18/27 threshold combinations), so it is out. Protocol is in no top-15 in the 4 scenarios where it is a candidate (mean importance 0.0007, below the noise floor); X1 does not exclude it, so it stays only because the final list is "pool minus exclusions". The Dst Port exclusion is the most consequential of the five that depend on the X1 thresholds (section 6).

### 5.3 E1 cells

| cell | rule | columns passing | after exclusions |
|---|---|---|---|
| 0 | top-10 in >= 50% of scenarios | 27 | 19 |
| 1 | top-15 in >= 50% | 36 | 27 |
| 2 | top-15 in >= 25% | 45 | 34 |
| fallback | every candidate (68) minus exclusions | 68 | 52 |

### 5.4 C1 results (AUC, mean of 5 paired seeds; baseline = pool minus X1 exclusions)

| cell | scenario | fold | baseline -> list | difference +/- SE | result |
|---|---|---|---|---|---|
| 0 (19) | att | 2017 | 0.9828 -> 0.9841 | +0.0013 +/- 0.0033 | PASS |
| 0 | att | 2018 | 0.6294 -> 0.5978 | -0.0316 +/- 0.0106 | FAIL |
| 0 | noatt | 2017 | 0.9781 -> 0.9906 | +0.0125 +/- 0.0023 | PASS |
| 0 | noatt | 2018 | 0.5879 -> 0.5187 | -0.0693 +/- 0.0121 | FAIL |
| 1 (27) | att | 2017 | 0.9828 -> 0.9729 | -0.0099 +/- 0.0015 | FAIL |
| 1 | att | 2018 | 0.6294 -> 0.6219 | -0.0075 +/- 0.0156 | PASS |
| 1 | noatt | 2017 | 0.9781 -> 0.9791 | +0.0011 +/- 0.0018 | PASS |
| 1 | noatt | 2018 | 0.5879 -> 0.5813 | -0.0066 +/- 0.0547 | PASS |
| 2 (34) | att | 2017 | 0.9828 -> 0.9868 | +0.0040 +/- 0.0029 | PASS |
| 2 | att | 2018 | 0.6294 -> 0.6749 | +0.0454 +/- 0.0034 | PASS |
| 2 | noatt | 2017 | 0.9781 -> 0.9882 | +0.0101 +/- 0.0021 | PASS |
| 2 | noatt | 2018 | 0.5879 -> 0.5419 | -0.0460 +/- 0.0211 | FAIL |

Cell 0 against the full pool (information only): fold 2017 passes in every row (-0.0011 to +0.0048); fold 2018 fails in every row (-0.0958 to -0.1354).

### 5.5 Decision

Cells 0, 1 and 2 each fail at least one row. The last cell failed, so the rule freezes `fallback_pool_minus_excluded.txt` as flow_v1 (52 columns).

## 6. Sensitivity to the conventions (measured on the cell-0 list)

- Ranking metric: family-balanced gives 19 columns, the plain "any attack" ranking gives 16; 10 in common.
- Usable-run threshold: AUC >= 0.60 or "every run counts" gives 21 columns, 15 in common with the declared 19. Usable fold-2018 runs: 11 (0.70), 36 (0.60), 40 (all).
- Nine columns survived each of these two perturbations separately: ACK Flag Count, Total Bwd packets, Total Length of Bwd Packet, Bwd Packet Length Max, Packet Length Max, Active Mean, Active Min, Active Max, Idle Mean. They form three twin groups, so three pieces of information. The rest of cell 0 depended on a convention.
- X1: five exclusions hold in only 18 of 27 threshold combinations (Bwd IAT Mean, Down/Up Ratio, Dst Port, Flow IAT Max, Fwd IAT Std). They are the first candidates for a test in a later version.

## 7. Limits - read before using the list

1. Two datasets only. The folds that ranked the columns also scored the check, so the lists have a selection advantage the baseline lacks. The check shows that shortening loses little *here*; it does not show generalisation to other networks.
2. After X1, fold 2018 sits near chance (0.52-0.68 across lists, single seeds up to 0.73). A difference there compares noise. The SE comes from RF seeds on one fixed pair of datasets, and pairing by seed is approximate. Cell 2 (34 columns) was better than the baseline in three of four rows (+0.045 +/- 0.003 in att/2018) and failed only in noatt/2018 (0.542 vs 0.588, both near chance). So a shorter list was not shown to be worse; it was not shown to be safe by the declared rule.
3. Flow-only columns without attacker-environment shortcuts do not transfer detection from 2017 to 2018 for DoS floods (Hulk, HOIC, LOIC) and SSH brute force. A rule or threshold fitted on one dataset's DoS or brute force should not be assumed to carry over to the other.
4. Many frozen columns have no demonstrated value (see section 1). Which of them the Prolog rules use is decided later and separately.
5. Conventions not derived from an experiment: usable AUC >= 0.70, noise floor 0.001, X1 thresholds 0.3 / 0.3 / 0.9, the chain of cells, top-k, "1 standard error", equal weight per family. Section 6 shows how far the result moves.
6. Unexplained: keeping Attempted rows raises fold-2018 AUC by about 0.06-0.09 in each of the four att/noatt pairs of the pooled run, although Attempted vectors are under 0.5% of the test set.
7. Small families: WebAttack without Attempted rows has 104 (2017) and 283 (2018) unique vectors (2,056 and 438 with them). Real brute force in 2018 is the 94,197 SSH vectors of Wednesday-14; all 2018 FTP vectors are Attempted (109 unique in total, 56 of them in Friday-16). Per-family coverage of cell 0 was flagged CHECK in 4/8 (BruteForce), 5/8 (WebAttack) and 4/8 (DoS) scenarios: no short list served all families.
8. context_v1 (backward-window source metrics) did not meet its pre-declared criteria on Brute Force (C1 0/4, C2 0/4, C3 4/4) and is not part of flow_v1. It was tested on brute force only, with one attacker IP per dataset and no real FTP in the 2018 training data; this is not evidence that context is useless for other families.

## 8. Changing the list

Any change is a new registry version (flow_v2) after a test. Excluded columns return only that way. Context metrics are a separate set. Raw files are untouched.

## 9. Reproduction

Folders (project root): `reports\select\pooled_v1` (8 scenarios and `shift_<Family>`), `reports\select\flow_v1_freeze` (select report, candidate lists, `columns.csv`, check reports in `vs_fallback` and `vs_fullpool`), `reports\select\check_fallback`, `check_c0`, `check_c1`, `check_c2`.
Scripts: `select_features.py` (with `--cache-main` for check runs), `column_shift.py`, `freeze_flow_v1.py`.
Order: `select_features.py` (8 scenarios, pooled, `--split-by dataset`) -> `column_shift.py` per family -> `freeze_flow_v1.py select` -> `select_features.py` check runs per cell (`--scenarios main-pp-noatt main-pp-att --skip-curve`) -> `freeze_flow_v1.py check --baseline-dir reports\select\check_fallback`.
