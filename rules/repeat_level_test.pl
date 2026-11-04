% repeat_level_test.pl -- expectations come from the decision table, NOT from the code.
% Run from the project root:
%   swipl -q -g run_tests -t halt prolog\rule_layer_v1\repeat_level_test.pl
:- use_module(library(plunit)).
:- use_module(repeat_level).

% case(Name, Network, [Window-Peak, ...], Expected)
case(c01_big_value_2017,        net2017, [120-110, 900-110, 1800-110], clear).
case(c02_one_below_each_2017,   net2017, [120-2,   900-14,  1800-19],  normal).
case(c03_borderline_at_1800,    net2017, [120-2,   900-2,   1800-22],  borderline).
case(c04_one_below_2018,        net2018, [120-44,  900-69,  1800-69],  normal).
case(c05_59_is_borderline,      net2018, [120-59,  900-69,  1800-69],  borderline).
case(c06_exactly_clear_from,    net2018, [120-60,  900-10,  1800-10],  clear).
case(c07_highest_over_windows,  net2018, [120-30,  900-80,  1800-80],  borderline).
case(c08_audited_public_source, net2018, [120-52,  900-52,  1800-52],  borderline).
case(c09_window_missing,        net2018, [120-45,  900-45],            unknown).
case(c10_unknown_network,       net2019, [120-50,  900-50,  1800-50],  unknown).
% two additions that test the ">=" decision at the borderline edge itself
case(c11_exactly_borderline,    net2018, [120-45,  900-10,  1800-10],  borderline).
case(c12_equal_edges_no_band,   net2017, [120-3,   900-2,   1800-2],   clear).

% malformed inputs must give unknown (addition: unknown is never "normal")
malformed(m1_negative_peak,    net2018, [120-(-1), 900-10, 1800-10]).
malformed(m2_float_peak,       net2018, [120-52.0, 900-10, 1800-10]).
malformed(m3_duplicate_window, net2018, [120-10, 120-90, 900-10, 1800-10]).
malformed(m4_extra_window,     net2018, [120-10, 900-10, 1800-10, 600-5]).

:- begin_tests(repeat_level).

test(decision_table) :-
    findall(Name-Expected-Got,
            ( case(Name, Net, Peaks, Expected),
              (   repeat_level(Net, Peaks, G0) -> Got = G0 ; Got = no_answer ),
              Got \== Expected ),
            Bad),
    (   Bad == []
    ->  true
    ;   format(user_error, "wrong levels (name-expected-got): ~w~n", [Bad]),
        fail
    ).

test(malformed_input_is_unknown) :-
    findall(Name-Got,
            ( malformed(Name, Net, Peaks),
              (   repeat_level(Net, Peaks, G0) -> Got = G0 ; Got = no_answer ),
              Got \== unknown ),
            Bad),
    (   Bad == []
    ->  true
    ;   format(user_error, "not unknown (name-got): ~w~n", [Bad]),
        fail
    ).

:- end_tests(repeat_level).