# Architectural Decisions — BrownOS Capability-Tag Probes

Session: ses_3c9c1235bffet1d6JH8iaOqlej
Started: 2026-02-07T18:32:48.770Z

## Design Choices

### Model Capability Upgrades (2026-02-07T15:45:00Z)
**Status**: ✓ Applied

Upgraded agent/category models to leverage available API keys (OpenAI + Anthropic):
- **oracle** → `openai/o3-pro` (variant: high) — Best pure-reasoning for logic puzzles
  - Fallback: gpt-5.2-pro, gpt-5.2
- **momus** → `openai/gpt-5.2-pro` (variant: high) — Enhanced compute for plan review
  - Fallback: gpt-5.2, claude-sonnet-4-5
- **explore** → `google/antigravity-gemini-3-flash` (variant: medium) — Fast pro-level reasoning
  - Fallback: gemini-3-flash-preview, claude-haiku-4-5
- **ultrabrain** → `anthropic/claude-opus-4-6` (variant: max) — 1M context for full problem state
  - Fallback: gpt-5.3-codex, gpt-5.2-pro

**Experimental**: Added `antigravity-gemini-3-pro-deep-think` to opencode.json provider section with `deep` thinking variant. Model ID confirmed working.

