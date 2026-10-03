# Model selection state

Existing `workforce/model_fabric.py` provides ModelRegistry, ModelRouter,
ModelSpec/Request/Response, a local Ollama adapter, health failure counts and a
no-model fallback. Candidate filters include capability/jurisdiction/input-cost
estimate; it is not a validated multi-provider spend-reservation system.

The integrated pipeline selects Tier D deterministic-no-model and sends no case
content to a model. OpenAI/Gemini/Claude/Grok/Qwen/DeepSeek/Mistral remote adapters
are not added. Frontier/balanced/small routing requires explicit adapter, privacy,
pricing and held-out evaluation work before operational use.
