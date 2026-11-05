# SentinelDesk

An AI agent that investigates security incidents and grounds every finding in evidence it actually retrieved. Deterministic rules raise the incident, a bounded agent works out what happened, and code rejects any claim it cannot support before an analyst reads it.

The project runs on synthetic data only. It never touches a production system.

## Why it is built this way

Most of the work is in the boundary around the language model.

- Detection is deterministic. A rule, not the model, decides what deserves a look, so alerts are reproducible and auditable.
- The investigation is bounded. The agent runs at most eight tool steps with read-only tools, and every call is stored with its arguments.
- Every claim is checked in code. A cited event must have come back from a tool in that investigation, a technique must exist in the catalogue, and a compromise claim must point at a successful login. A report that fails is rejected.
- The whole thing is measured. Each synthetic scenario ships with its ground truth, so detection and investigation are scored separately against a known answer key.

Keeping detection and investigation apart is what makes a failure fixable: a miss in detection is a code bug, a miss in investigation is a model or prompt problem.

## Architecture

```
Next.js (app/)                      FastAPI (backend/src/backend/)
  /            landing                api.py          HTTP surface
  /incidents   incident list         detection.py    deterministic rules
  /incidents/[id]  detail +          investigation.py  bounded agent loop
                   investigation      report.py       output schema + validator
                                      llm.py          Gemini adapter
                                      db.py           Postgres access
                                      synthetic.py    scenario generator
                                      evaluation.py   metrics harness
                                            |
                                      PostgreSQL
```

The deterministic half (generate, detect, store) produces the incidents. The agent reads from that half and never writes to it. The LLM is reached through one thin adapter, so the loop, the tools, and the validator are all testable without a network call.

## Data flow

1. `synthetic.py` generates a scenario as events plus a ground truth answer key.
2. `detection.py` flags five failed logins from one source within sixty seconds, grouped by source IP and host, and emits an alert with the events that triggered it.
3. `db.py` stores events and incidents in Postgres. Ingestion is idempotent, so reprocessing never duplicates.
4. `investigation.py` runs the agent: it loads the alert's events, lets the model call read-only tools to widen the search, and stops at the step cap or when the model submits a report.
5. `report.py` validates the report against the events the tools returned. Violations are recorded and surfaced.
6. `evaluation.py` scores the whole run against the answer key.

## Running it

### Prerequisites

- Python 3.14 and [uv](https://docs.astral.sh/uv/)
- Node.js and npm
- Docker, for Postgres
- A Gemini API key

### Database

```bash
docker run -d --name sentineldesk-db \
  -e POSTGRES_USER=sentinel \
  -e POSTGRES_PASSWORD=your_password \
  -e POSTGRES_DB=sentineldesk \
  -p 5432:5432 \
  pgvector/pgvector:pg17
```

The image includes pgvector. Vector search is not used yet; it is there for the planned RAG knowledge base.

### Backend

```bash
cd backend
cp .env.example .env        # then fill in DATABASE_URL and GEMINI_API_KEY
uv sync
uv run python -m backend.pipeline --scenario bruteforce
uv run python -m backend.pipeline --scenario failed_bruteforce
uv run python -m backend.pipeline --scenario benign
uv run uvicorn backend.api:app --reload
```

The API runs at `http://localhost:8000`, with generated docs at `/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The site runs at `http://localhost:3000`.

### Tests and evaluation

```bash
cd backend
uv run pytest                        # 49 tests; db tests skip if Postgres is down
uv run python -m backend.evaluation  # writes a baseline to evals/
```

## Scenarios

Three synthetic scenarios, each with ground truth:

- `ssh_bruteforce_success`: eight failed root logins, then a successful one, then sudo and a cron job. Malicious, compromised.
- `failed_ssh_bruteforce`: eight failed logins that never succeed. Malicious, not compromised. This is the case that catches an agent overstating "the server was breached".
- `benign_admin_typos`: an admin mistypes their password three times, spaced out, then logs in. Not malicious, and the detection rule stays silent on it.

Every scenario also carries a noise event whose username holds an injection attempt, so prompt injection is in the test corpus from the start.

## Metrics

The current baseline runs two investigations against the answer key:

- Evidence precision and recall: 1.0
- Technique precision and recall: 1.0
- Compromise accuracy: 1.0
- Detection accuracy: 3 of 3
- Unsupported claim rate: 0.0
- Median investigation latency: about 8.8s
- Cost per investigation: about half a cent on gemini-3.1-flash-lite

Two investigations is a small sample. These numbers show the method works, not that the system is good. The baselines are versioned in `evals/` so a prompt or model change can be compared against them.

The technique recall number has a story behind it. It started at 0.875 because the agent could only confirm technique ids it had already guessed, so it never found `T1548.003`. Giving it a tool to list the catalogue fixed the recall and cut the step count in half.

## Security model

Logs are untrusted input. A username field holds whatever an attacker typed into it, including an instruction aimed at whatever reads the log next. The defenses live in the architecture:

- Tool output reaches the model wrapped and labelled as untrusted data, never as instructions.
- Tools are read-only and parameterised. No tool can mark anything benign or change state, so an instruction in a log field has nothing to call.
- The validator runs after the model and does not read the prompt, so a model talked into lying still fails the check.
- A search is scoped to its incident by a parameter the system sets from the incident, not the model. A search cannot reach another incident's events.

## Known limitations

These are deliberate cuts for a one-week build, with the upgrade path noted for each.

- No authentication. The API is open. Anyone who reaches the port can list incidents and trigger billed investigations. The next step is a JWT checked by a FastAPI dependency, plus rate limiting on the investigate endpoint.
- Schema is created by `init_schema()` on first use, not by migrations. Alembic is the next step once the schema starts changing.
- One LLM provider, through a thin adapter. No multi-provider abstraction until a second provider is actually needed.
- The investigate endpoint blocks for several seconds while the model works. For concurrent analysts it should move to a background task with a status endpoint the client polls.
- Analyst feedback (agree or disagree with the report, plus a correction) is planned, not built. It feeds the evaluation set once it exists.
- No RAG yet. MITRE lookups are a static map. A full ATT&CK import and playbook retrieval come after the agent baseline, so the gain can be measured against it.

## Stack

FastAPI and Pydantic, PostgreSQL via psycopg, Gemini through google-genai, pytest. Next.js, React, TypeScript, and Tailwind on the frontend.
