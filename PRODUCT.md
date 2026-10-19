# Product

<!-- impeccable:product-schema 1 -->

## Platform

web, terminal

## Users

Rookhold is primarily for individual developers building agents that execute generated snippets, code-interpreter features, user-defined transforms, evaluators, graders, automation, and small self-hosted tools.

Developers connecting Claude Code, Hermes, OpenCode, or another MCP host to a separate executor are the secondary audience. Platform and security engineers who need gVisor hardening, signing-key controls, deployment evidence, and detailed policy are the tertiary audience.

## Product Purpose

Rookhold runs short Python, Node.js, and Bash jobs with hard limits, live output, and a verifiable receipt. Success begins when a new developer gets a result in under two minutes, then can answer what ran, which controls became effective, what output or violations were observed, and how the run ended.

## Positioning

Rookhold is the smallest reliable execution boundary a developer can add to an AI agent or application. It owns one problem: an application received code, must not hand it the host machine, and needs to know what happened afterward. Rookhold is not an LLM, agent framework, persistent workspace, browser environment, remote IDE, or general-purpose cloud sandbox.

## Operating Context

- Developers begin with `rookhold run` or one SDK `run()` call. The command can manage a temporary local development service when no endpoint is configured and must state that this mode is unisolated.
- Trusted applications, agent harnesses, and MCP adapters submit short stateless jobs over HTTP.
- Developers and operators use the CLI or embedded dashboard to create a run, monitor its ordered event stream, cancel eligible work, and inspect result, policy, receipt, and signed evidence.
- Claude Code, OpenCode, Codex, Hermes, OpenClaw, and other MCP hosts launch the same `rookhold-mcp` stdio adapter; the host owns the conversation UI while Rookhold owns execution policy and evidence.
- Local development may use the explicitly unisolated subprocess provider. The guarded Linux x86_64 deployment uses one pinned gVisor workload per job on a dedicated VM.
- The API and persisted store remain the source of truth; the terminal client, MCP adapter, and dashboard are views over those contracts.

## Capabilities and Constraints

- Preserve the existing submit, list, filter, inspect, cancel, live-output, event, result, record, exact artifact download, and copy workflows.
- Preserve scoped identity and tenant context, the six-class isolation contract, requested-versus-effective policy, output truncation evidence, receipt integrity metadata, and explicit trust warnings.
- The dashboard is a single dependency-free HTML/CSS/JavaScript document embedded in the Rust server and protected by exact Content Security Policy hashes.
- The Python package's `rookhold-cli` and `rookhold-mcp` commands use only the standard library and share the typed client contract.
- No dashboard state may become a competing source of truth or imply that server-provided evidence was independently verified.
- The operator surface must work with narrow screens, keyboard navigation, zoom/reflow, reduced motion, and high-contrast preferences.

## Brand Commitments

Keep the name Rookhold and its plainspoken, technically honest voice. Security posture must be legible without theatrics: never imply stronger isolation, attestation, or verification than the server actually reports. The replacement interface should feel like a current production control plane rather than a terminal-themed demo or a collection of decorative cards.

## Evidence on Hand

- Product and operating contract: `README.md`, `SECURITY.md`, and `docs/`.
- Embedded operator surface and behavior: `crates/coop-server/src/dashboard.html`.
- API, CSP, and dashboard contract tests: `crates/coop-server/src/routes.rs`.
- Canonical visual system and responsive rules: `DESIGN.md`.
- Current release captures: `assets/console-v0.6.png` and `assets/rookhold-cli-mcp-demo.gif`.
- No customer logos, testimonials, usage claims, or external brand assets are available and none may be fabricated.

## Product Principles

1. A new developer must reach a successful run in under two minutes.
2. The common execution path must require one CLI command or one SDK method.
3. Every security claim must correspond to observed evidence, never configuration alone.
4. Rookhold remains a bounded job runner, not a general-purpose remote computer.
5. Roadmap priority comes from developer use cases, not architectural completeness.
6. Show results first and make the receipt the memorable proof of what happened.
7. Keep requested policy, observed controls, and independently verifiable evidence distinct.
8. Fail closed in behavior and use plain language in every developer-facing surface.

## Accessibility & Inclusion

Preserve semantic landmarks, labels, focus order, visible focus, keyboard operation, status announcements, responsive reflow, zoom resilience, reduced-motion handling, and contrast-safe status communication. Visual status must never rely on color alone.
