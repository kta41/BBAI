# Architecture proposal for `bbai`

## Summary

The project is designed as a local research assistant for Bug Bounty and Web Security investigations. It sits between the researcher and one or more local LLM backends, primarily Ollama, while keeping all data persisted locally.

## Why this structure

A simple wrapper around `ollama run` would not be enough for an investigation workflow. We need:

- target/project management
- evidence capture
- session continuity
- hypothesis tracking
- structured findings
- human validation
- future tool calling and RAG

The architecture therefore separates concerns into CLI, domain logic, providers, context builders, storage, and tools.

## Layer responsibilities

### CLI

This layer only handles user interaction:

- validate arguments
- display output
- delegate to service objects
- stay free of domain logic

### Core

This layer contains the domain models and operations around:

- targets
- assets
- endpoints
- evidence
- observations
- hypotheses
- findings
- sessions
- reports

### LLM provider

The LLM layer is abstracted behind a provider interface so the rest of the application does not depend directly on Ollama calls. A provider interface can later support:

- local Ollama
- OpenAI-compatible endpoints
- other local backends

### Context builder

The prompt sent to the model should be structured, not a generic string. The context builder composes details such as:

- target and scope
- recon observations
- evidence collected
- previous findings and hypotheses
- user question

This is the foundation for future semantic memory and RAG.

### Storage

SQLite is the right default for the MVP because it is local, low-friction, and enough for structured workflows. SQLAlchemy provides the object model, and Alembic versions schema changes while adopting existing SQLite workspaces without replacing their data.

### Tools

External tool integrations should be represented through a small tool abstraction with:

- name
- description
- input schema
- execute implementation

This makes it possible to add `httpx`, `subfinder`, `ffuf`, or future security scanners without coupling the rest of the system.

## Security boundaries

The assistant is not designed to be an autonomous agent that executes irreversible actions without approval. The core idea is to provide analysis and context support while the human remains in control.

The system should enforce the following principles:

- local-only analysis by default
- no arbitrary command execution from LLM output
- human approval before any external action that changes state
- clear evidence trails for every finding

## Future path

The next iterations can add:

- SQLite FTS5 search and later semantic retrieval
- more advanced authenticated-session handling
- a supervised, checkpointed workflow engine
- a local frontend that reuses the same domain services as the CLI
- operational features such as backup, restore, and workspace portability

## Minimum viable architecture

```text
CLI
  ↓
Workspace
  ↓
Context Builder
  ↓
LLM
  ↓
Tool Calling
  ↓
Security/Scope Policy
  ↓
External Security Tools
  ↓
Evidence Store
  ↓
Findings
  ↓
Reviewer
  ↓
Report
```

This keeps the project realistic for the first phase while leaving room for expansion without a large refactor.
