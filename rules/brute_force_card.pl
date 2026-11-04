% brute_force_card.pl -- rule card as data (decisions: card fields, vocabulary, units, case key).
:- module(brute_force_card, [card_id/1, card_field/3, required_field/1]).

card_id(brute_force).

required_field(F) :-
    member(F, [version, source, observable, exception, technique, acceptance, case_key, time_scope]).

% card_field(CardId, Field, Value) -- all clauses kept together on purpose.
card_field(brute_force, version, rule_layer_v1).

% sources: src(Name, Reliability, Note)
card_field(brute_force, source, src(zeek_ssh_script, primary, 'read from the script itself: 30 failed SSH connections / 30 min per source, with a source exclusion list')).
card_field(brute_force, source, src(zeek_ftp, primary, '20 attempts / 15 min')).
card_field(brute_force, source, src(wazuh_5712, secondary, 'NOT verified: 8 events / 120 s in 4.x, 6 / 120 in old v2.0 files')).
card_field(brute_force, source, src(et_2001219, secondary, 'NOT verified: 5 SYN / 120 s per source, forum quotes only')).
card_field(brute_force, source, src(attack_capec_cwe, primary, 'T1110, CAPEC-49, CWE-307: definition only, verify the numbers yourself')).

% observables: observable(Name, Class, Status)   Class: direct | proxy | weak | gap
card_field(brute_force, observable, observable(auth_service, direct, used_v1)).
card_field(brute_force, observable, observable(repeated_contact, proxy, used_v1)).
card_field(brute_force, observable, observable(session_reached_auth, proxy, untested)).
card_field(brute_force, observable, observable(graceful_close, proxy, untested)).
card_field(brute_force, observable, observable(low_volume, proxy, untested)).
card_field(brute_force, observable, observable(partial_request, proxy, untested)).
card_field(brute_force, observable, observable(duration, proxy, untested)).
card_field(brute_force, observable, observable(syn_without_reply, proxy, untested)).
card_field(brute_force, observable, observable(rst_flags, weak, untested)).
card_field(brute_force, observable, observable(packet_size_pattern, weak, untested)).
card_field(brute_force, observable, observable(failed_auth, gap, recorded)).
card_field(brute_force, observable, observable(success_after_failure, gap, recorded)).
card_field(brute_force, observable, observable(username, gap, recorded)).
card_field(brute_force, observable, observable(attempts_inside_one_connection, gap, recorded)).
card_field(brute_force, observable, observable(distributed, gap, recorded)).
card_field(brute_force, observable, observable(slow_below_window, gap, recorded)).
card_field(brute_force, observable, observable(encrypted_content, gap, recorded)).
card_field(brute_force, observable, observable(offline_cracking, gap, recorded)).

% exceptions: exception(Name, Origin, Note)
card_field(brute_force, exception, exception(known_scanner, from_sources, 'context fact available; no rule uses it yet')).
card_field(brute_force, exception, exception(nat_gateway, writer_guess, 'needs the user judgment')).
card_field(brute_force, exception, exception(scheduled_service, writer_guess, 'needs the user judgment')).
card_field(brute_force, exception, exception(retrying_service_account, writer_guess, 'needs the user judgment')).
card_field(brute_force, exception, exception(long_completed_session, writer_guess, 'needs the user judgment')).

% technique: human-assigned. The flow cannot tell sub-techniques apart, so the parent is recorded.
card_field(brute_force, technique, technique('T1110', 'TA0006', parent_only)).

% acceptance: criteria as written by the user (date as recorded by the user), before any attack measurement.
card_field(brute_force, acceptance, acceptance(written('2026-10-29'), field1, 'main attack episode alarms at ALL primary points of the dataset')).
card_field(brute_force, acceptance, acceptance(written('2026-10-29'), field2, 'first alarm before the attacker sent 100 flows to the same target')).
card_field(brute_force, acceptance, report_only([attempted, portscan, secondary_points])).
card_field(brute_force, acceptance, frozen_record('CALIBRATION + MEASUREMENT v1', closed('2026-10-29'))).

% case key and time scope
card_field(brute_force, case_key, [src_ip, dst_ip, dst_port]).
card_field(brute_force, time_scope, time_scope(capture_day, dataset_artifact, 'live Wazuh: a retention parameter, not a detection threshold; decided in the Wazuh phase')).

% units (terms fixed): alarm episode, case, source-case
card_field(brute_force, unit, def(alarm_episode, 'times where the window count reaches T or more; alarms closer than W merge')).
card_field(brute_force, unit, def(case, 'one (source, target, port) in the time scope; judged by the rule')).
card_field(brute_force, unit, def(source_case, 'one source across all its cases; used for competition with scan')).
card_field(brute_force, unit, inequality('per day: alarming sources =< alarming cases =< alarm episodes')).

% facts every case carries (used by the knowledge axis)
card_field(brute_force, case_fact, episode_count).
card_field(brute_force, case_fact, first_time).
card_field(brute_force, case_fact, last_time).
card_field(brute_force, case_fact, window_peak).

% vocabulary: five words
card_field(brute_force, vocabulary, word(auth_service, defined)).
card_field(brute_force, vocabulary, word(repeat_level, defined([normal, borderline, clear]))).
card_field(brute_force, vocabulary, word(scan_like, defined_later(needs_all_ports_table))).
card_field(brute_force, vocabulary, word(known_scanner, context_fact)).
card_field(brute_force, vocabulary, word(network, selects_registry_row)).

% repeat_level over the three windows: highest wins
card_field(brute_force, repeat_level_rule, max_over_windows(clear, borderline, normal)).