# Vendors and runtimes: what the catalog contains and where it comes from

The data lives in `canary/vendors.json` and is merged with an optional `vendors.local.json` (see
[design.md](design.md)). Everything below was checked in October 2026 against the vendor's own documentation, model
cards or source code where a link is given; entries marked "not confirmed" were not found in a vendor document and are
included because the domain exists and is commonly used. Vendors and runtimes change their endpoints: treat the catalog
as a starting point and edit it.

A host that matches a vendor's domains is tagged `vendor_domain:<id>` (medium). That tag means only "a local model has
no obvious reason to contact this site"; it says nothing about the vendor's intentions. The region note is the
company's registered or headquarters country, given because some users have rules about where data may go.

## Vendors

| id | Vendor / family | Hugging Face org | Cloud API hosts (a local model should not need them) | Source |
|---|---|---|---|---|
| qwen | Alibaba Qwen | `Qwen` | `dashscope-intl.aliyuncs.com`, `dashscope.aliyuncs.com` (CN, not confirmed in docs), `chat.qwen.ai`, `qwen.ai` | [Alibaba Cloud Model Studio](https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope), Qwen model cards on HF |
| deepseek | DeepSeek | `deepseek-ai` | `api.deepseek.com`, `platform.deepseek.com`, `chat.deepseek.com` | [DeepSeek API docs](https://api-docs.deepseek.com/), DeepSeek-V3 model card |
| moonshot | Moonshot AI (Kimi) | `moonshotai` | `api.moonshot.ai`, `api.moonshot.cn`, `platform.moonshot.ai`, `kimi.com` | [Kimi API docs](https://platform.moonshot.ai/docs/guide/start-using-kimi-api) |
| mistral | Mistral AI | `mistralai` | `api.mistral.ai`, `console.mistral.ai`, `chat.mistral.ai` | [Mistral API](https://docs.mistral.ai/api/) |
| zhipu | Zhipu AI / Z.ai (GLM) | `zai-org` (formerly `THUDM`, now empty) | `api.z.ai`, `open.bigmodel.cn`, `chatglm.cn` | [Z.ai quick start](https://docs.z.ai/guides/overview/quick-start), [BigModel docs](https://docs.bigmodel.cn/cn/guide/start/quick-start) |
| minimax | MiniMax | `MiniMaxAI` | `api.minimax.io`, `api.minimaxi.com` (not confirmed in docs) | [MiniMax platform](https://platform.minimax.io/docs/api-reference/text-openai-api) |
| meta | Meta Llama | `meta-llama` | `api.llama.com`, `llama.com`, `meta.ai` (the hosted Llama API may be discontinued: not confirmed) | Meta web pages found by search; verify before relying on them |
| google | Google Gemma | `google` | `generativelanguage.googleapis.com`, `ai.google.dev`, `aistudio.google.com` | [Gemini API OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai) |
| microsoft | Microsoft Phi | `microsoft` | `ai.azure.com`, Azure inference endpoints are per-tenant (`*.services.ai.azure.com`) | Azure AI documentation; no fixed global API host |
| openai | OpenAI gpt-oss | `openai` | `api.openai.com`, `chatgpt.com` | OpenAI client libraries (the docs page itself could not be fetched automatically) |
| nvidia | NVIDIA Nemotron | `nvidia` | `integrate.api.nvidia.com`, `build.nvidia.com` | [NVIDIA NIM API reference](https://docs.api.nvidia.com/nim/reference/llm-apis) |
| cohere | Cohere (Command) | `CohereLabs` (formerly `CohereForAI`, now empty) | `api.cohere.com`, `api.cohere.ai`, `dashboard.cohere.com` | [Cohere compatibility API](https://docs.cohere.com/docs/compatibility-api) |
| ibm | IBM Granite | `ibm-granite` | `*.ml.cloud.ibm.com` (e.g. `us-south.ml.cloud.ibm.com`), `watsonx.ai` | [watsonx.ai API](https://cloud.ibm.com/apidocs/watsonx-ai) |
| 01ai | 01.AI (Yi) | `01-ai` | `api.lingyiwanwu.com`, `01.ai` | [01.AI platform](https://platform.lingyiwanwu.com/docs), Yi model card |
| baidu | Baidu ERNIE | `baidu` | `qianfan.baidubce.com`, `aip.baidubce.com`, `yiyan.baidu.com` | [Qianfan docs (international)](https://intl.cloud.baidu.com/doc/qianfan/index.html); the `/v2` path found by search |
| tencent | Tencent Hunyuan | `tencent` | `api.hunyuan.cloud.tencent.com`, `hunyuan.tencentcloudapi.com` | [Tencent Cloud Hunyuan](https://cloud.tencent.com/document/product/1729/111007) |
| xiaomi | Xiaomi MiMo | `XiaomiMiMo` | `api.xiaomimimo.com`, `platform.xiaomimimo.com`, `aistudio.xiaomimimo.com` | MiMo model card, [MiMo API quick start](https://mimo.mi.com/docs/en-US/quick-start/summary/first-api-call) |
| stepfun | StepFun (Step) | `stepfun-ai` | `api.stepfun.com`, `api.stepfun.ai` | Step-3.5-Flash model card |
| xai | xAI (Grok) | `xai-org` | `api.x.ai`, `grok.com` | [xAI docs](https://docs.x.ai/docs/overview) |
| bytedance | ByteDance Seed | `ByteDance-Seed` | `ark.cn-beijing.volces.com`, `volcengine.com`, `volces.com` | [Volcengine Ark docs](https://www.volcengine.com/docs/82379/1399008) |
| ant | Ant Group inclusionAI (Ling/Ring) | `inclusionAI` | `tbox.cn` (exists; API host not confirmed) | HF org listing |
| meituan | Meituan LongCat | `meituan-longcat` | `api.longcat.chat`, `longcat.chat` | HF org listing (host not confirmed) |
| shanghai-ai-lab | Shanghai AI Laboratory (InternLM) | `internlm` | `intern-ai.org.cn` | HF org listing |
| openbmb | OpenBMB / ModelBest (MiniCPM) | `openbmb` | `modelbest.cn`, `openbmb.cn` | HF org listing |
| tii | TII Falcon | `tiiuae` | `falconllm.tii.ae`, `tii.ae` | HF org listing |
| liquid | Liquid AI (LFM) | `LiquidAI` | `api.liquid.ai`, `liquid.ai` | HF org listing |
| ai21 | AI21 Labs (Jamba) | `ai21labs` | `api.ai21.com`, `ai21.com` | HF org listing |
| allenai | Allen Institute for AI (OLMo) | `allenai` | `allenai.org` | HF org listing |
| upstage | Upstage (Solar) | `upstage` | `api.upstage.ai`, `upstage.ai` | HF org listing |
| lg | LG AI Research (EXAONE) | `LGAI-EXAONE` | `lgresearch.ai` | HF org listing |
| arcee | Arcee AI (Trinity) | `arcee-ai` | `api.arcee.ai`, `arcee.ai` | HF org listing |
| huggingface-tb | Hugging Face SmolLM | `HuggingFaceTB` | none of its own (uses the Hub) | HF org listing |

The Hugging Face organisations were checked on 2026-10-28 with `https://huggingface.co/api/models?author=<org>`; every
org above returns models. "HF org listing" means the org exists and the company domain resolves; no API document was
read for that row.

Model weights are normally hosted on the Hugging Face Hub (`huggingface.co`) and, for several Chinese vendors, also on
ModelScope (`modelscope.cn`) and the Ollama registry (`registry.ollama.ai`). These hubs are tagged `hub_domain:<id>`
(info): downloading weights is expected once, but a run that is meant to be offline should not contact them.

Hosted inference or aggregation services (OpenRouter, Together, Groq, Fireworks, SiliconFlow, the Hugging Face router,
SambaNova, Perplexity) are tagged `hosted_api:<id>` (medium) because a prompt sent there leaves the machine.

## Runtimes

| id | Runtime | Default listen address | API flavours | Known outbound calls | Source |
|---|---|---|---|---|---|
| llama.cpp | `llama-server` | `127.0.0.1:9931` on current master (8080 in older builds and Docker examples) | OpenAI `/v1/chat/completions`, Anthropic `/v1/messages` | None by default. `-hf` downloads from Hugging Face; `-mu` any URL; `-dr` Docker Hub; experimental `--connect` tunnel and agent/MCP tools are off by default. `--offline` forbids network access | [server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md), `common/common.h`, `tools/server/server.cpp` |
| vllm | vLLM | `8000` | OpenAI chat and completions, Anthropic `/v1/messages`, Responses | Usage statistics are on by default and POSTed to `stats.vllm.ai` (heartbeat every 10 minutes); opt out with `VLLM_NO_USAGE_STATS=1` or `DO_NOT_TRACK=1`. The `/docs` page loads assets from the internet unless `--enable-offline-docs` | [usage stats](https://docs.vllm.ai/en/latest/usage/usage_stats.html), [usage_lib.py](https://github.com/vllm-project/vllm/blob/main/vllm/usage/usage_lib.py), [online serving](https://docs.vllm.ai/en/latest/serving/online_serving/) |
| sglang | SGLang | `30000` | OpenAI, native `/generate`, Anthropic `/v1/messages`, Ollama-compatible | No telemetry found in the docs or in `server_args.py` (search not exhaustive); Hugging Face downloads | [SGLang docs](https://docs.sglang.io/basic_usage/send_request.html), `anthropic_api.mdx`, `ollama_api.mdx` |
| ollama | Ollama | `11434` | native `/api/chat`, OpenAI `/v1`, Anthropic-compatible | Model pulls from `registry.ollama.ai`; the desktop app checks `ollama.com/api/update`; cloud models and web search use `ollama.com` when signed in. Disable cloud with `OLLAMA_NO_CLOUD=1` or `"disable_ollama_cloud": true` in `~/.ollama/server.json` | [FAQ](https://docs.ollama.com/faq), [cloud](https://docs.ollama.com/cloud), `envconfig/config.go`, `app/updater/updater.go` |
| lmstudio | LM Studio | `1234` (`/v1`) | OpenAI-compatible | The app checks for updates at launch (version, build, OS), downloads models and runtimes from Hugging Face and LM Studio hosts; documented as having no telemetry | [privacy](https://lmstudio.ai/app-privacy), [offline](https://lmstudio.ai/docs/app/offline) |
| tgi | Text Generation Inference | `3000` (Docker examples map `8080:80`) | OpenAI Messages API | Usage statistics on by default, POSTed to `huggingface.co/api/telemetry/tgi`; `--usage-stats off` | `launcher/src/main.rs`, `router/src/usage_stats.rs` in the repository |
| mlx-lm | `mlx_lm.server` | `127.0.0.1:8080` | OpenAI `/v1/chat/completions` | Hugging Face downloads | `mlx_lm/server.py` |
| trtllm | `trtllm-serve` | `localhost:8000` | OpenAI-compatible | Hugging Face downloads | `tensorrt_llm/commands/serve.py` |
| basalt | Basalt | `127.0.0.1:8080` | OpenAI, Anthropic | Has its own Security monitor serving `/api/netwatch/*` | Basalt repository |
| strata | Strata | `127.0.0.1:8080` | OpenAI, Anthropic | None known; no monitor | [Strata README](https://raw.githubusercontent.com/jesdga95/strata/main/README.md) |
| generic | any OpenAI-compatible server | `127.0.0.1:8080` | OpenAI | unknown | |

Libraries built on `huggingface_hub` (transformers, vLLM, TGI, mlx-lm and others) contact the Hub for files unless
`HF_HUB_OFFLINE=1`; their telemetry is off with `HF_HUB_DISABLE_TELEMETRY=1` or `DO_NOT_TRACK=1`
([environment variables](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables)).

## Known gaps

- Endpoints change. The Meta hosted API in particular may have moved; the Microsoft and IBM cloud hosts are per-region
  or per-tenant, so only a suffix can be listed.
- Rows marked "HF org listing" were not checked against an API document.
- Phone-home behaviour was read from documentation and source at the time of writing; a newer version can differ.
  The point of the canary is to observe, not to rely on this table.
- A vendor domain matching is a hint for a human to look at, not a verdict.
