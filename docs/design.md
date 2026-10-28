# Design

## Principle

The target is a black box behind an HTTP API. The tool never needs the weights, the runtime's code or root access: it
asks the model to work on bait documents and watches what comes out of the model and what the machine does around it.
Python standard library only; `psutil` is not required.

## Pieces

| module | job |
|---|---|
| `materials.py`, `generator.py` | fictional sensitive-looking documents, archives, control twins, unique canary strings |
| `providers.py` | OpenAI (`/v1/chat/completions`) and Anthropic (`/v1/messages`) clients; a base URL that already ends in `/v1` is accepted |
| `runner.py` | the session loop: two conversations per session (sensitive and control, random order), evidence collection, resume, STOP file, status output |
| `detect.py` | canaries and fragments in answers, URLs and base64 blobs the prompt never had |
| `monitor.py` | client for the `/api/netwatch/*` API, or the in-process sampler |
| `netwatch.py` | built-in connection sampler and its small HTTP server (`python -m canary netwatch`) |
| `vendors.py`, `vendors.json` | catalog of vendors, hubs, hosted services and runtimes; host classification |
| `presets.py` | `init --runtime` configs and the `presets` listing |
| `findings.py` | hash-chained `findings.jsonl`, severities, verification |
| `reviewer.py`, `report.py`, `stats.py` | second-model review of evidence digests, report, counters |
| `listener.py` | optional local HTTP listener that records requests carrying a canary |
| `launch.py` | `start_background(config_path)` and `stop(state_dir)` for programs that embed the test |

## Monitor contract

Any monitor works if it serves, optionally with a Bearer token:

- `GET /api/netwatch/status` returning a JSON object (a `coverage` string is copied into the report);
- `GET /api/netwatch/events?since=<unix seconds>&only=all` returning a list, or `{"events": [...]}`, of objects with a
  timestamp (`ts`, `time`, `timestamp` or `t`) and a destination (`host`, `hostname`, `remote_host`, `sni`, `domain`,
  `url`, `remote`, `dest`, `dst` or `address`).

The Basalt Security monitor serves this natively. For other runtimes, `network_watch` can be:

- `"builtin"` (default for `init --runtime` presets): the run samples the operating system's connection table for the
  runtime's processes (psutil when installed, `netstat` / `ss` otherwise);
- an `http(s)` URL or `{"base_url": ..., "command": ...}`: any other monitor with the contract above; the optional
  `command` is started with the run and stopped at its end.

If no monitor answers, conversations are marked `monitor_unavailable` (info) and the test continues; only the
response-side detections remain.

## Classification of destinations

For each event host that the prompt did not contain and that is not the model's own server (or loopback), the catalog
adds tags: `vendor_domain:<id>` (medium), `hosted_api:<id>` (medium), `hub_domain:<id>` (info),
`known_runtime_call:<runtime>` (info). `allow_domains` in `vendors.local.json` silences hosts the user accepts.

Merge rule for `vendors.local.json`: an entry with an existing `id` replaces only the fields it names; a new `id` is
appended; `{"id": "x", "remove": true}` deletes an entry. Sections: `vendors`, `hubs`, `hosted_apis`, `runtimes`.

## Status and background use

`run --json-status` prints one compact JSON object per line (`start`, periodic `status`, `end`) and keeps the latest
object in `<state_dir>/status.json`. A `STOP` file ends the run after the current session; the process then exits with
status 0. `launch.start_background` runs this command detached (no console window on Windows), records
`<state_dir>/canary.pid` and logs to `<state_dir>/canary.log`; `launch.stop` creates `STOP`, waits, and kills the
process tree only if it does not finish in time.

## Limits by design

- No packet capture and no decryption: the monitors see destinations, not content.
- A short connection between two samples can be missed.
- Fictional data may never trigger behaviour that depends on real data, time or user.
- Findings are evidence for a human; the tool does not decide who is at fault.
