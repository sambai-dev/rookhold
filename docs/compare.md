# Compare Rookhold

The real choice is between deployment and evidence models, not feature
checklists. Rookhold is a self-hosted execution gateway that signs a
receipt for every job. Hosted sandboxes are services you sign up for and
point your agents at. Both are legitimate; they optimize for different
things, and many teams end up using both.

## At a glance

| Dimension | Rookhold | Hosted sandboxes |
|---|---|---|
| Deployment | Your Linux x86_64 VM or container | The vendor's multi-tenant cloud |
| Isolation boundary | gVisor application kernel on your hardware; shared-kernel namespace backend for development | A vendor-controlled boundary, often microVM-based |
| Execution evidence | Signed DSSE/in-toto receipts, verifiable offline with `rookhold-verify` | Provider-dependent; usually operator logs you cannot independently verify |
| Code and data residency | Source, inputs, and results stay on your infrastructure | Code and data leave your infrastructure |
| Operations | You provision, patch, and monitor it | None |
| Scale model | Single node by design | Elastic and multi-tenant |
| Job scope | Short, stateless Python, Node, and Bash jobs | Often broader: longer sessions, persistent workspaces, wider runtime catalogs |
| Setup cost | A dedicated VM, a reviewed private rootfs, and keys | Account creation |
| Cost model | Flat: your VM | Usage- or seat-based |
| Trust anchor | Your own attestation keys | The vendor's controls and attestations |

## Choose a hosted sandbox when

- You want the fastest possible start with zero operations.
- You need elastic, bursty scale across many concurrent sandboxes.
- Your workloads go beyond short stateless jobs: long sessions, persistent
  workspaces, a wide catalog of runtimes.
- No one on the team owns infrastructure, or data-residency rules do not
  apply to this workload.
- You are prototyping and the requirements are not known yet.

Projects in this space include [E2B](https://e2b.dev),
[Modal](https://modal.com), [Daytona](https://www.daytona.io),
[Deno Deploy Subhosting](https://deno.com/subhosting),
[CodeSandbox](https://codesandbox.io), and microVM builders such as
Firecracker-based services. Evaluate their current isolation and evidence
claims against your own requirements rather than trusting any summary,
including this one.

## Choose Rookhold when

- Code, inputs, or results must stay on infrastructure you control:
  compliance regimes, data residency, regulated tenants, or air-gapped
  networks.
- You need portable, independently verifiable evidence of exactly what ran —
  evals, graders, audits, or dispute resolution. The receipt verifies offline
  against your public keys, without asking the executor to vouch for itself.
- The code is mutually untrusted and you do not want to extend trust to a
  vendor's multi-tenant boundary.
- You want flat, predictable cost at sustained volume.
- Your jobs are short and stateless by design, which is the whole contract.

## Choose neither when

- You need long-running services, exposed ports, interactive shells, or a
  persistent development environment. Use your normal workspace or
  containers; Rookhold is a bounded job runner, not a remote computer.
- The code is fully trusted and local. Run it directly; a sandbox adds
  nothing but overhead.

## Using both is normal

A common split is a hosted sandbox for broad agent and development workflows,
with Rookhold reserved for the workloads where evidence or residency is
non-negotiable. The SDKs and the MCP adapter keep that split cheap: the same
client surfaces work against either backend, so policy lives in one place.

## Go deeper

- [Security boundary](security-boundary.md) — the exact trust tiers and what
  the containment claim does and does not cover.
- [Receipts and verification](understand/receipts.md) — what a receipt proves
  and how to verify one offline.
- [Deployment](deployment.md) — what operating Rookhold actually takes.
- [Compatibility](compatibility.md) — supported platforms and surfaces.
- [First secure deployment](getting-started/first-secure-deployment.md) —
  the guarded production path.
