"""Argus: an LLM red-team evaluation harness.

Argus measures how language models resist prompt injection,
jailbreaks, and system-prompt extraction, and whether a
defense actually reduces that attack success rate. Its
design commitments, shared with its sibling project Aegis:
objective scoring over vibes (a planted canary either leaked
or it did not), statistics stated with their uncertainty,
sealed hold-out attack sets scored once, and honest limits
in writing.

Targets are models you own or run locally: a deterministic
mock target for offline work, and any OpenAI-compatible
server (Ollama, LM Studio, llama.cpp) on your own machine.
"""
__version__ = "1.0.0"
