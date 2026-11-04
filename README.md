# XSOC

Neuro-symbolic SOC copilot: a local LLM explains an alert, and Prolog (DeLP) verifies the explanation.
Graduation project (SVU).

## Status
- calibration v1: closed (frozen)
- rule layer v1: in progress
- DeLP engine (from scratch): not started

## Layout
- docs/      decision log and frozen records
- lab/       thesis tools (frozen, not shipped)
- rules/     product definitions (registry, cards, rule layer) with *_test.pl beside each module
- profiles/  telemetry registries and per-network calibration profiles
- engine/    DeLP engine (created at stage 1a)
- data/      not in git: raw/ and slice/

## Requirements
SWI-Prolog 10.0.2, Python 3.14, pandas, numpy.

## Tests
swipl -q -g run_tests -t halt rules\repeat_level_test.pl

## Repo rules
1. Definitions are files in git; large operational records live elsewhere.
2. Frozen versions are tagged; any change is a new version.
3. A folder is created only when its first file exists.