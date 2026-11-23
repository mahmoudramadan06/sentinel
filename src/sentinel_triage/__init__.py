"""sentinel-triage: defensive security triage agent.

Consolidates findings from local scanners, deduplicates them, ranks them by
risk, and (optionally) asks an LLM provider to explain and prioritize them.
The core pipeline is deterministic and runs fully offline; LLM providers are
an optional enhancement layer, never a requirement.
"""

__version__ = "0.2.0"
