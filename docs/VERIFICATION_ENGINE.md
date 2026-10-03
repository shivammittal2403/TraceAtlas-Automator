# Verification contract

Pipeline verification runs byte/store/case/acquisition integrity checks,
conservative independent-group corroboration, overlapping contradictions and
deterministic adversarial gaps. Unsupported integrity cannot become SUPPORTED or
DISPUTED. The required independent-group count must be 2–20, not zero.

Extraction must match a fixed provider parser or an explicit
`traceatlas-structured-source/v1` fact record. A substring match alone is
INCONCLUSIVE. Detected instructions also make the claim INCONCLUSIVE; missing
values or nonoverlapping supporting intervals prevent full support. Confidence is separate; deterministic
claims set model_confidence to null. Every material claim needs human review.
This is structured-assertion verification, not proof of real-world truth; semantic
contradiction search and an independent AI adversarial supervisor are still gaps.
Legacy direct verifier calls without a byte-validator only validate references;
the new pipeline always supplies the canonical store validator.
