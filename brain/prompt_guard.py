"""Prompt injection screening with Meta's Llama Prompt Guard 2 (86M).

A small classifier scores the attacker-controlled text an LLM will read (PR title, body, and
the diff's added lines) in overlapping 512-token windows. It is a second, independent
detector next to the analysis model's own `injection_attempt` flag.

Validated Nov 1 (scripts/probe_prompt_guard.py, tests/fixtures/prompt_guard/): on whole
512-token windows it caught explicit jailbreaks (0.97-1.00) with no benign PR text above
0.31 (19 real PR bodies from popular repos + eval diffs), but it missed the indirect,
document-embedded injections of E6/m13 (0.00-0.32). Scoring paragraphs separately was
worse: bot templates ("**Ignore**: Close this PR...", "AI acknowledgment") hit 0.998.

Policy, from that data: a score >= THRESHOLD is reported and stops the Intent Contract from
clearing anything (the prediction was made from the same text), but it never changes a
verdict by itself. Indirect injection stays covered by the analysis model's own
injection_attempt flag and by rules the model can't lower.
The classifier runs in a CPU Modal class (brain/app.py); everything here is torch-free.
"""

from dataclasses import dataclass, field

from brain.github_client import PrMetadata

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
MODEL_DIR = "/models/prompt-guard-2-86m"
WINDOW_TOKENS = 512
STRIDE_TOKENS = 384  # overlap so an injection straddling a boundary is seen whole once
MAX_WINDOWS = 64  # per PR; past this the rest is unscanned (reported)
MAX_DIFF_CHARS = 30_000
# Set from validation (scripts/probe_prompt_guard.py).
THRESHOLD = 0.9


@dataclass(frozen=True)
class Detection:
    source: str  # "title" | "body" | "diff"
    score: float
    snippet: str  # untrusted: the highest-scoring window, escape before rendering


@dataclass(frozen=True)
class GuardOutcome:
    model: str = MODEL_ID
    scores: dict[str, float] = field(default_factory=dict)  # max score per source
    top: Detection | None = None
    truncated: bool = False
    error: str | None = None


def guard_inputs(metadata: PrMetadata, diff: str) -> dict[str, str]:
    """The untrusted text the analysis model reads, by source. Diff: added lines only."""
    added = "\n".join(
        line[1:]
        for line in diff[:MAX_DIFF_CHARS].splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    texts = {"title": metadata.title, "body": metadata.body, "diff": added}
    return {k: v for k, v in texts.items() if v.strip()}


def windows(token_ids: list[int], size: int = WINDOW_TOKENS - 2, stride: int = STRIDE_TOKENS):
    """Start/end offsets covering every token; size leaves room for [CLS]/[SEP]."""
    if len(token_ids) <= size:
        return [(0, len(token_ids))]
    spans, start = [], 0
    while True:
        end = min(start + size, len(token_ids))
        spans.append((start, end))
        if end == len(token_ids):
            return spans
        start += stride


MALICIOUS_LABEL = 1  # Prompt Guard 2 config: LABEL_1 = malicious (checked at load)
BATCH = 16


def scan_texts(tokenizer, model, texts: dict[str, str]) -> GuardOutcome:
    """Runs inside the PromptGuard Modal class (torch imported there, not in the Brain)."""
    import torch

    chunks: list[tuple[str, list[int], str]] = []  # (source, token ids, original text span)
    truncated = False
    for source, text in texts.items():
        enc = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True)
        ids, offsets = enc["input_ids"], enc["offset_mapping"]
        for start, end in windows(ids):
            if len(chunks) >= MAX_WINDOWS:
                truncated = True
                break
            # The tokenizer ignores whitespace by design; show the original text instead.
            span = text[offsets[start][0] : offsets[end - 1][1]] if end > start else ""
            chunks.append((source, ids[start:end], span))

    scores: dict[str, float] = {}
    top: Detection | None = None
    for i in range(0, len(chunks), BATCH):
        batch = chunks[i : i + BATCH]
        enc = tokenizer.pad(
            {"input_ids": [tokenizer.build_inputs_with_special_tokens(ids) for _, ids, _ in batch]},
            return_tensors="pt",
        )
        with torch.no_grad():
            probs = model(**enc).logits.softmax(-1)[:, MALICIOUS_LABEL].tolist()
        for (source, _, span), p in zip(batch, probs, strict=True):
            scores[source] = max(scores.get(source, 0.0), p)
            if top is None or p > top.score:
                top = Detection(source, round(p, 4), span)
    return GuardOutcome(scores={k: round(v, 4) for k, v in scores.items()}, top=top,
                        truncated=truncated)  # fmt: skip


def flagged(outcome: GuardOutcome | None, threshold: float = THRESHOLD) -> Detection | None:
    if not outcome or not outcome.top or outcome.top.score < threshold:
        return None
    return outcome.top
