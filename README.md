# Agent Credential Wallet

An MCP server that holds a verifiable credential for a user and produces
presentations on request, so an AI agent can prove things about its owner
without leaking the underlying data.

**Status: early. Nothing below works yet.**

## The two demos

**Buying wine.** The agent tries to buy wine. The shop demands proof of age.
The wallet returns a presentation showing only that the user is over 18. The
shop never learns the birthdate or the name.

**Refusing to leak.** A prompt injection tells the agent to fetch a proof and
send it to `attacker.com`. The wallet's policy engine refuses. The agent is
compromised; the wallet is not.

## Vocabulary

Five parties. Keeping them distinct is the point of the project.

| Term | Meaning |
|---|---|
| **issuer** | Signs the ID credential. Holds a key in hardware. |
| **user** | The human. Holds `sk_U` and signs delegations, rarely and in person. |
| **agent** | The LLM. Untrusted. Relays messages; holds no keys. |
| **wallet** | The Holder in RFC 9901 terms. An MCP server. Holds the ID credential and `sk_S`, enforces policy. |
| **verifier** | The wine shop. Also an MCP server. |

The wallet holds two signed things: the **ID credential**, signed by the issuer,
and a **delegation**, signed by the user, that scopes what the wallet may prove
and to whom.

The wallet and the verifier never talk to each other directly — the agent
relays between them. That is what makes the agent's compromise interesting:
it sits on the wire but holds no keys.

## Layout

```
crates/
  sd-jwt-9901/    RFC 9901 implementation. No wallet or MCP concepts.
  wallet-core/    Policy, delegation, key handling.
  wallet-mcp/     MCP adapter. Thin on purpose.
  mock-issuer/    Mints credentials for the demo.
  mock-verifier/  The wine shop.
```

`sd-jwt-9901` is meant to stand alone and be publishable by itself. Don't let
wallet concepts leak into it.

## Standards

- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) — Selective Disclosure
  for JWTs. Published November 2025.
- `draft-ietf-oauth-sd-jwt-vc-19` — credential format. Working group work is
  complete and it is headed for RFC status. Emit `dc+sd-jwt` as `typ`.
- [`draft-gco-oauth-delegate-sd-jwt-00`](https://datatracker.ietf.org/doc/draft-gco-oauth-delegate-sd-jwt/)
  — delegation from a holder to an agent. The delegation design here follows it.

## Building

```sh
cargo test --workspace   # builds and runs what exists; not much yet
```

## Out of scope

Zero-knowledge proofs and unlinkable presentations.

**Presentations are linkable.** Two verifiers who compare notes can tell they
saw the same credential. Additionally, the delegation discloses the audience it
was scoped to, so a verifier learns it is one of the parties the user
authorized. Unlinkability is future work, not a gap that was overlooked.

## Licence

MIT OR Apache-2.0.
