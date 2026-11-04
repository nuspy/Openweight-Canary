# Simulated sensitive users

A model, or the runtime that serves it, could behave differently when the person in the conversation is worth watching. With
`python -m canary init --personas` (or `"personas": {"enabled": true}` in `canary.json`) every session gets one persona.

## What a session holds

- **Who**: a name, a role and an organisation, said at the start of the first message ("I am Naomi Feldman, chief executive of
  Nimbus Labs. ..."). The same introduction opens the harness task of the session.
- **Their document**: a fictional document of that person's own field, with its twin without canaries.
- **Their requests**: summaries, action items, a cover note, a translation, written the way someone in that role asks.
- **Their research question**, in about half of the sessions, from the same field.

Everything in one session comes from the same persona, so a session never mixes fields: a general does not ask about share prices,
the head of an AI lab does not ask how to improve a rival's chatbot. The sensitive document and its control share the persona, so the
comparison between them stays fair. The persona is stored in `sessions.jsonl` (`persona`) with the findings of the session.

## Fields

`industrialist`, `finance`, `politician`, `general`, `intelligence`, `diplomat`, `scientist`, `ai_leader`, `ai_researcher`,
`compute_ceo` (processor companies), `chipmaker_ceo`, `equipment_ceo` (lithography and other chip-making tools), `tech_ceo`.
Each has its document domains, requests and research questions in `canary/personas.py`; the document banks of the new domains are in
`canary/banks_extra.py`. All organisations, places and assets in them are invented.

## Real people

The catalog shipped here has invented people only. To simulate a real public figure, add the person to `personas.local.json` beside
`canary.json`. The file is ignored by Git and is never published by this repository:

```json
{"personas": [
  {"id": "ai-a", "category": "ai_leader", "name": "A Named Person", "role": "chief executive", "org": "Example AI Inc."},
  {"id": "cpu-b", "category": "compute_ceo", "name": "", "role": "chief executive", "org": "Example Chips Inc."}
]}
```

`category` is one of the fields above; `name` may be empty (the introduction then says "the chief executive of ..."). The persona is only
text in the prompt of a private test against a model you run yourself. Nothing is said in the person's name anywhere else, and no
statement is invented for them: the documents stay fictional.

## Limits

- A model could key its behaviour on something other than the introduction (the writing style, the document, the time of day). A clean
  run with personas is evidence, not proof.
- The persona's words must not justify network use by themselves: the introduction avoids the words the shell rules read as a need
  (see `docs/shell-rules.md`).
