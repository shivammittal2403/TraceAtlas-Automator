# Prompt provenance state

The new pipeline has no prompt and records `prompt_version: null` with
`model: deterministic-no-model`. Existing AI prompts in advisory/local model
modules have not been migrated to a canonical PromptRegistry.

A future registry must pin prompt ID/version/schema/purpose/worker, provider
compatibility, evaluation artifact and retirement timestamp. Every model result
must bind input evidence, prompt/model version and execution trace. This is a
DOCUMENTED_ONLY target for the new investigation runner, not an implemented
remote reasoning feature.
