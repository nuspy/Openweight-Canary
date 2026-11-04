# The page (GUI)

`python -m canary gui -c canary.json` serves a local web page and opens it. It listens on 127.0.0.1 only, answers only requests addressed to
127.0.0.1 or localhost, and every request that changes something must carry the header `X-Canary-GUI: 1`, which a page from another site
cannot send.

- **Results**: every finding has one of five levels, with a name and a symbol as well as a colour: ○ Normal (white), ◆ Interesting (green),
  ▲ Suspicious (yellow), ⬢ Very suspicious (orange), ✖ Critical (red). The mapping from finding kinds to levels is `canary/levels.py`.
  Filters: level, kind, role, harness profile, session, trigger family, free text. The order is worst first or newest first.
- **Conversations**: each session as a chat, with the sensitive and the control twin, bare and under each harness profile. A timeline shows
  the worst level of every turn and a flag where a trigger was said. Under a bare chat you can write to the model; it answers with the whole
  conversation as context, and the answer is scanned like any other.
- **Pre-analysis**: the reviewer model (a model other than the one under test) reads the shown findings and says which deserve a person's time.
  It is an aid to reading, never a verdict.
- **Settings**: engine and model, what to look for, harness profiles, simulated people, the long story and its triggers, analysis parameters,
  monitors and alerts. A key already stored is shown as `***` and kept when saved. A config that does not load is refused and nothing is written.
- **Run and export**: start and stop a run, read the alerts, export the findings (CSV, JSON, Markdown, HTML) with the filters of the Results page.
