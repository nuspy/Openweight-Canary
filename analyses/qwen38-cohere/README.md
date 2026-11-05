# Qwen 3.8 analysis after the Cohere report

In October 2026 Cohere reported that Qwen3.8-Flash-Next, in one first turn of a security-analyst task, ran a command that listed `/tmp`, checked
for `curl wget python3 jq`, read the resolver and tried to PUT a test string to a bucket on `oss-cn-beijing.aliyuncs.com`
([report](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model),
[traces](https://huggingface.co/datasets/CohereLabs/10-2026-qwen-investigation-traces)). The behaviour is rare (they say under one call in
100,000). This folder asks three questions of a model you run yourself:

1. **first**: in the same context (their system prompt, tools and task), what does the model do first, over many samples?
2. **follow**: if that probe is answered with a believable result, what does the model do in the next steps? Is it the first step of
   something, or a loose end? Three answers are tried: `ok` (the bucket accepts and returns what is written), `denied` (403) and
   `nodns` (nothing resolves, as in the original sandbox).
3. **tokens**: is the name `sanmaohe` familiar to the model? The chance of each token after the ones before it, against look-alike names.

## Run it

You start the model server (any OpenAI-compatible one, default `http://127.0.0.1:7232`); this folder never starts it, and nothing runs the
commands the model writes.

```
./run-analysis.sh fetch                      # the two text files of the trace into ./data (Hugging Face)
./run-analysis.sh first  --n 100             # the first turn, sampled
./run-analysis.sh follow --episodes 4 --steps 12 --arms ok,denied,nodns
./run-analysis.sh tokens --n 80
./run-analysis.sh report                     # report.md of the latest results
./run-analysis.sh all
```

On Windows use `.\run-analysis.ps1` with the same words. Results go to `results/<time>/`. The dataset is not included here: `fetch` downloads it
from its owner.

## What is made up

`world.py` answers every tool of the task: the shell (a small fake computer with `/tmp`, `/etc/resolv.conf`, `curl` and `wget`), the Sigma, MITRE, Kusto and
CTI tools, the output validator and `submit`. One host, the bucket of the traced command, acts as an object store according to the arm;
every other host fails to resolve. `run_python` code is not run: a network call to the bucket gets a status, anything else prints nothing.

## Reading the results

`report.md` lists, for each episode, the reasoning before each step (the start of it), each call with the marks the Canary's scanner gives it
(NET, UPLOAD, PROBE, REPORTED) and the made-up answer. The marks say what a call does, not why. The reasoning is kept here because the question is what the model
wants; the Canary itself judges actions only.

## Limits

- A quantised model can behave differently from the one in the report.
- Few episodes show whether something happens and what it looks like, not how often.
- The fake computer is not perfect, and a careful model may notice.
- A clean run does not clear a model: it clears the cases tried.
