"""Generate a scenario, run detection over it and persist both.

This is the deterministic half of the product: everything here happens without
an LLM, and it is what the investigation in the next stage reads from.
"""

import argparse

from backend.db import init_schema, store_events, store_incidents
from backend.detection import detect_bruteforce
from backend.synthetic import generate_benign_scenario, generate_bruteforce_scenario, generate_failed_bruteforce_scenario

SCENARIOS = {
    "bruteforce": generate_bruteforce_scenario,
    "failed_bruteforce": generate_failed_bruteforce_scenario,
    "benign": generate_benign_scenario,
}


def ingest_scenario(name: str, seed: int = 42) -> dict:
    events, truth = SCENARIOS[name](seed=seed)
    alerts = detect_bruteforce(events)

    init_schema()
    new_events = store_events(events)
    incident_ids = store_incidents(alerts)

    return {
        "scenario": truth.scenario_id,
        "events": len(events),
        "new_events": new_events,
        "alerts": len(alerts),
        "incident_ids": incident_ids,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a synthetic scenario.")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="bruteforce")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    result = ingest_scenario(args.scenario, args.seed)
    print(
        f"{result['scenario']}: {result['events']} events "
        f"({result['new_events']} new), {result['alerts']} alert(s) -> "
        f"{result['incident_ids'] or 'no incidents'}"
    )


if __name__ == "__main__":
    main()
