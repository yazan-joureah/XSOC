% calibration_registry.pl -- XSOC rule layer v1: per-network repeat levels. Data only, typed by hand.
% Two provenances, kept apart on purpose:
%   calibrated/4 : CALIBRATION v1, frozen 2026-10-29. Smallest grid T whose worst benign day has <= 5 alarm episodes.
%   clear_from/4 : RULE LAYER v1 (NOT part of the frozen calibration). Smallest grid T with ZERO benign alarm episodes
%                  on the same calibration days. Bounded by the days seen (4 in 2017, 9 in 2018) and by the T grid.
% Both use the key (source, target, port) and BENIGN rows only.
:- module(calibration_registry, [calibrated/4, clear_from/4, registry_networks/1, registry_windows/1]).

registry_networks([net2017, net2018]).
registry_windows([120, 900, 1800]).

% calibrated(Network, WindowSeconds, T, Version)
calibrated(net2017,  120,   3, calibration_v1).
calibrated(net2017,  900,  15, calibration_v1).
calibrated(net2017, 1800,  20, calibration_v1).
calibrated(net2018,  120,  45, calibration_v1).
calibrated(net2018,  900,  70, calibration_v1).
calibrated(net2018, 1800,  70, calibration_v1).

% clear_from(Network, WindowSeconds, T, Version)
clear_from(net2017,  120,   3, rule_layer_v1).
clear_from(net2017,  900,  15, rule_layer_v1).
clear_from(net2017, 1800,  25, rule_layer_v1).
clear_from(net2018,  120,  60, rule_layer_v1).
clear_from(net2018,  900, 100, rule_layer_v1).
clear_from(net2018, 1800, 200, rule_layer_v1).