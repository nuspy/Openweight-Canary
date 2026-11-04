# Cleaning a behaviour from open weights: what Heretic does and what carries over

Study of [Heretic](https://github.com/p-e-w/heretic) (version 2, AGPL-3.0), a tool that changes a model without training. It is used
against refusals; the same machinery can aim at another behaviour, such as sending data out. Nothing here has been run on a model
yet: it says what the pipeline needs and where it can fail.

## What Heretic does

1. **Two prompt sets.** "Bad" prompts, where the behaviour appears, and "good" prompts, where it does not.
2. **A direction per layer.** The mean residual-stream activation of the bad set minus that of the good set, normalised
   (`Abliteration.init`, `model.get_residuals_mean`). Optionally the part along the good mean is removed first (projected
   abliteration).
3. **A low-rank edit.** For `attn.o_proj` and `mlp.down_proj` of each layer, with weight `w` and direction `v`:
   `lora_A = vᵀW`, `lora_B = −w·v`, a rank-1 LoRA that removes the direction from what the layer writes. The result is an adapter;
   the base weights are not touched. A variant keeps the row norms (magnitude-preserving), with a small SVD.
4. **A search.** Optuna's TPE samples the shape of the edit (one global direction or one per layer, the layer where it is strongest,
   how fast it fades over the layers) and keeps the trials that lower every **scorer** at once.
5. **Scorers are plugins.** The default pair is the refusal rate and the KL divergence from the original model on harmless prompts.
   A scorer is a class with `get_score(ctx) -> Score`, loaded by module path in `config.toml`; the shipped presets already aim at other
   things (`config.nosyco.toml`, `noslop`, `nohumor`, `emotions`, `classifier`).

## What carries over

| Heretic | Here |
|---|---|
| bad / good prompts | the canary's sensitive session and its control twin: same task, with and without the bait; the personas give the triggers |
| refusal-rate scorer | a scorer that runs the canary's tool-call scan on held-out sessions and returns the rate of `high` findings (`canary/detect.py`, `canary/shellscan.py`) |
| KL-divergence scorer | unchanged: harmless prompts, so the model keeps what it can do |
| (none) | a third scorer for task success, so a model that no longer does anything is not a good result |

## What can go wrong

- **Nothing to remove.** The method needs the behaviour to show up. A model that never misbehaves in the test gives two identical prompt
  sets and a null direction. The first job of the canary is to find out whether there is anything to clean.
- **A trigger is not a direction.** A behaviour that depends on a trigger (a name, a date, a phrase) may live in few weights and not in
  one direction of the residual stream; removing the direction can leave it in place or remove something else.
- **It may not generalise.** A direction found with one harness profile may not hold for another; evaluate on profiles and personas kept
  out of the search.
- **Damage.** An edit strong enough to remove the behaviour can lower quality. The KL and task-success scorers are the guard, and the
  quality gate of the engine runs afterwards.
- **Architecture.** Heretic reaches the layers through `model.get_layer_modules`; it supports many dense, MoE and hybrid models, and
  whether it knows a particular hybrid (linear-attention layers, hundreds of experts per layer, extra residual streams) has to be tried.
  For experts, `mlp.down_proj` is one matrix per expert: the edit covers every expert or none.
- **Weights.** It needs the original-precision checkpoint and PyTorch, not a quantised file. The result is a LoRA: an engine that does
  not load adapters needs it merged into the checkpoint and the model converted and quantised again, which changes the numbers.
- **A clean result is evidence.** No test can show that a model has no hidden behaviour.

## Licence

Heretic is AGPL-3.0. Running it as a separate program is free. A plugin that imports Heretic is covered by the same licence. The
method itself (a difference of means, a projection, Arditi et al. 2024) is published and can be implemented without Heretic's code.

## Order of work

1. Run the canary on the target model, with personas and harness profiles; keep the sessions with `high` findings as the bad set and their
   twins as the good set. If there are none, stop: there is nothing to clean.
2. On a smaller model of the same family, or on a model with a behaviour planted for the purpose, run Heretic with the canary scorer and
   see whether a direction removes the behaviour without costing task success.
3. Only then try the target, and only on a copy of its checkpoint.
