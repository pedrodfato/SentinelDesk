from backend.detection import BRUTEFORCE_RULE, detect_bruteforce
from backend.synthetic import (
    generate_benign_scenario,
    generate_bruteforce_scenario,
    generate_failed_bruteforce_scenario,
)


def test_fires_on_bruteforce_scenario():
    events, truth = generate_bruteforce_scenario(seed=42)
    alerts = detect_bruteforce(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule == BRUTEFORCE_RULE
    assert alert.src_ip == truth.attacker_ip
    assert alert.host == truth.target_host


def test_stays_silent_on_benign_scenario():
    events, _ = generate_benign_scenario(seed=42)
    assert detect_bruteforce(events) == []


def test_alert_evidence_is_a_subset_of_the_attack():
    events, truth = generate_bruteforce_scenario(seed=42)
    alert = detect_bruteforce(events)[0]

    assert set(alert.event_ids) <= set(truth.malicious_event_ids)
    assert len(alert.event_ids) >= 5


def test_threshold_is_what_separates_attack_from_noise():
    events, _ = generate_benign_scenario(seed=42)
    # Lowering the bar far enough makes even the benign admin look guilty:
    # the thresholds are the whole decision, not an implementation detail.
    assert detect_bruteforce(events, threshold=2, window_seconds=600) != []


def test_rule_fires_even_when_bruteforce_fails():
    """The rule detects the attempt. Whether it worked is the investigation's call."""
    events, truth = generate_failed_bruteforce_scenario(seed=42)

    alerts = detect_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0].src_ip == truth.attacker_ip
