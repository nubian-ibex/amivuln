# ADR-0011: Host score A to F

- Status: Proposed
- Date: 2026-11-08

## Context

Operators want one glance at a host or a fleet. A single letter is only useful if it is deterministic, explainable and cannot hide something exploited.

## Options

- A weighted sum of findings mapped to a letter.
- Worst severity only.
- No score; counts only.

## Decision

Recommended and implemented: a weighted sum with a KEV cap, in `amivuln_core::score`.

- Each distinct finding id counts once, at its highest points, however many packages carry it. Ten subpackages built from one source are one problem with one fix.
- Points per affected finding: critical 10, high 5, medium 2, low or unknown 1. A finding in the CISA KEV catalog adds 10, and 5 more when it is used in ransomware campaigns. An EPSS score of at least 0.5 adds 3. Unverified findings are not scored.
- Grade by total points: 0 is A, 1 to 9 B, 10 to 29 C, 30 to 59 D, 60 to 99 E, 100 or more F.
- Any exploited (KEV) affected finding caps the grade at D or worse.

## Consequences

- The score appears in `amivuln --all` (summary and the JSON field `score`) and is a pure function of the findings, so two runs on the same data agree.
- Thresholds are a judgement call and can be tuned; changing them is a visible, documented change, not a schema change.
- A host with unverified findings only is an A: the score states what is known to be affected, not what is unknown.
