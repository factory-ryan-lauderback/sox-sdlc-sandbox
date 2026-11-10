# Fake Jira store (sandbox only)

File-backed stand-in for Jira project FRQ, used until the real Jira API token is available.
Written only through `.sox/agents/jira_cli.py` by agent workflows on `main` (compare-and-swap on
`jira.json` via the Contents API). Identities recorded here are asserted by the writing workflow,
not by Jira, so they are weaker evidence than a real Jira changelog. Not a control path; never merged.
