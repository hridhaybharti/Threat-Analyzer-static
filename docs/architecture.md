# Architecture

Signal Flow
-----------
- Input (URL/IP/domain) -> API layer -> Service -> Engine
- Engine composes independent signals from `engine/signals/*` and aggregates them
- Verdict produced by `engine/verdict.py`

Risk Scoring
------------
- Signals have `impact`, `confidence`, and `strength` which are weighted
- Scores normalized to 0-100 range

Verdict Logic
-------------
- `MALICIOUS` for high scores or any critical signals
- `SUSPICIOUS` for mid-range scores
- `LOW_RISK` for low-but-nonzero scores
- `BENIGN` otherwise
