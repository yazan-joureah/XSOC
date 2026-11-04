% repeat_level.pl -- XSOC rule layer v1, layer 2: window peaks -> repeat level.
% Pure logic, no numbers of its own: thresholds come ONLY from calibration_registry.
% Levels: normal < borderline < clear. Anything that cannot be judged is `unknown`, never `normal`.
:- module(repeat_level, [window_level/4, repeat_level/3]).
:- use_module(calibration_registry).

% window_level(+Network, +WindowSeconds, +Peak, -Level)
% Peak = highest flow count seen in any window of that length for one case. ">=" matches calibration (count >= T alarms).
window_level(Net, W, Peak, Level) :-
    integer(Peak), Peak >= 0,
    calibrated(Net, W, Borderline, _),
    clear_from(Net, W, Clear, _),
    (   Peak >= Clear      -> Level = clear
    ;   Peak >= Borderline -> Level = borderline
    ;   Level = normal
    ).

% repeat_level(+Network, +Peaks, -Level)   Peaks = [Window-Peak, ...], one entry per registry window.
% Highest level over the windows wins. Unknown network, missing/duplicate/extra window or a bad peak -> unknown.
repeat_level(Net, Peaks, Level) :-
    (   valid_input(Net, Peaks),
        registry_windows(Ws),
        findall(L, ( member(W, Ws), member(W-P, Peaks), window_level(Net, W, P, L) ), Levels),
        length(Ws, N), length(Levels, N)          % a window the registry could not judge must not vanish silently
    ->  highest(Levels, Level)
    ;   Level = unknown
    ).

highest(Levels, Level) :-
    (   memberchk(clear, Levels)      -> Level = clear
    ;   memberchk(borderline, Levels) -> Level = borderline
    ;   Level = normal
    ).

valid_input(Net, Peaks) :-
    atom(Net),
    registry_networks(Ns), memberchk(Net, Ns),
    is_list(Peaks),
    maplist(is_pair, Peaks),
    registry_windows(Ws),
    forall(member(W-_, Peaks), memberchk(W, Ws)),     % no window outside the registry
    forall(member(W, Ws), peak_for(W, Peaks)).        % each window exactly once, with a valid peak

is_pair(W-_) :- integer(W).

peak_for(W, Peaks) :-
    findall(P, member(W-P, Peaks), [P]),
    integer(P), P >= 0.