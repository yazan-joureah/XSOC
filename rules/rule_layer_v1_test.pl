% rule_layer_v1_test.pl -- checks on the registry and the card (data only).
% Run from the project root:
%   swipl -q -g run_tests -t halt prolog\rule_layer_v1\rule_layer_v1_test.pl
:- use_module(library(plunit)).
:- use_module(calibration_registry).
:- use_module(brute_force_card).

% Independent copy of the frozen table (CALIBRATION SUMMARY v1, primary episodes), typed separately on purpose.
frozen_v1(net2017,  120,  3).
frozen_v1(net2017,  900, 15).
frozen_v1(net2017, 1800, 20).
frozen_v1(net2018,  120, 45).
frozen_v1(net2018,  900, 70).
frozen_v1(net2018, 1800, 70).

:- begin_tests(registry).

% check 1: the six borderline numbers equal the frozen v1 table (nothing extra, nothing missing)
test(borderline_equals_frozen_v1) :-
    findall(N-W-T, calibrated(N, W, T, _), Rows),
    findall(N-W-T, frozen_v1(N, W, T), Frozen),
    subtract(Rows, Frozen, Extra),
    subtract(Frozen, Rows, Missing),
    (   Extra == [], Missing == []
    ->  true
    ;   format(user_error, "registry differs from frozen v1. extra: ~w missing: ~w~n", [Extra, Missing]),
        fail
    ).

% check 2: in every window the clear level is not below the borderline level
test(clear_not_below_borderline) :-
    findall(N-W-B-C, ( calibrated(N, W, B, _), clear_from(N, W, C, _), C < B ), Bad),
    (   Bad == []
    ->  true
    ;   format(user_error, "clear_from below borderline: ~w~n", [Bad]),
        fail
    ).

% check 3a: every (network, window) has exactly one row per predicate, with the right version tag
test(rows_complete_and_tagged) :-
    registry_networks(Ns),
    registry_windows(Ws),
    findall(N-W,
            ( member(N, Ns), member(W, Ws),
              \+ ( findall(V1, calibrated(N, W, _, V1), [calibration_v1]),
                   findall(V2, clear_from(N, W, _, V2), [rule_layer_v1]) ) ),
            Bad),
    (   Bad == []
    ->  true
    ;   format(user_error, "rows missing, duplicated or wrongly tagged for: ~w~n", [Bad]),
        fail
    ).

% check 3b: no unknown network or window, and every T is a positive integer
test(no_unknown_rows_and_values_positive) :-
    registry_networks(Ns),
    registry_windows(Ws),
    findall(Row,
            ( (   calibrated(N, W, T, _), Row = calibrated(N, W, T)
              ;   clear_from(N, W, T, _), Row = clear_from(N, W, T)
              ),
              \+ ( memberchk(N, Ns), memberchk(W, Ws), integer(T), T > 0 ) ),
            Bad),
    (   Bad == []
    ->  true
    ;   format(user_error, "invalid rows: ~w~n", [Bad]),
        fail
    ).

:- end_tests(registry).

:- begin_tests(card).

% decision A: a card without all required fields is rejected
test(card_has_all_required_fields) :-
    card_id(Id),
    findall(F, ( required_field(F), \+ card_field(Id, F, _) ), Missing),
    (   Missing == []
    ->  true
    ;   format(user_error, "missing card fields: ~w~n", [Missing]),
        fail
    ).

:- end_tests(card).