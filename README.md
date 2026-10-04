# Agent Credential Wallet

An agent wallet that holds a delegated credential for an AI agent and
produces presentations on request, so the agent can prove things about its
owner without leaking the underlying data, and without ever holding a key
itself. The agent reaches the wallet through an MCP interface.

**Status: early. Nothing below works yet.**

## The two demos

**Buying wine.** The agent tries to buy wine. The shop demands proof of age.
The agent wallet returns a presentation showing only that the user is over 18.
The shop never learns the birthdate or the name.

**Refusing to leak.** A prompt injection tells the agent to fetch a proof and
send it to `attacker.com`. The agent wallet refuses, because the user's
policy doesn't allow `attacker.com`. The agent is compromised; the agent
wallet is not.

## The idea

Issuers sign credentials with ML-DSA. A user's wallet holds them, as wallets
do today, plus one feature a next generation of wallets could have: the user
can sub-issue a credential to an agent by signing a **sub-credential**, again
with ML-DSA. The sub-credential carries the user's policy for the agent: which
claims may be proven, to which verifiers, until when. Because the policy is
inside the signed sub-credential, anyone can check it, not just the wallet.

The agent never receives the sub-credential or any key. Its LLM reads
untrusted input and may misbehave. Instead, a separate **agent wallet** holds
the two signed objects and its own key, `sk_S`. When the agent asks for a
presentation, the agent wallet checks the request against the policy and only
then signs. The agent reaches the agent wallet through an MCP interface: the
interface carries messages, and the wallet is the security boundary.

## Vocabulary

Five parties. Keeping them distinct is the point of the project.

| Term | Meaning | Holds |
|---|---|---|
| **issuer** | Signs the ID credential. | Issuer key, in hardware |
| **user wallet** | The user's own wallet. Receives credentials and issues sub-credentials, rarely and with the user present. In this repo a CLI stands in for it. | ID credential, `sk_U` |
| **agent** | The LLM. Untrusted. Relays messages. | Nothing |
| **agent wallet** | One per agent. Enforces the user's policy and produces presentations, unattended. Reached through an MCP interface. | ID credential with only the delegated disclosures, sub-credential, `sk_S` |
| **verifier** | The wine shop. Also an MCP server. | Issuer's public key |

The trust chain runs issuer → user wallet → agent wallet. The ID credential
carries `pk_U` in its `cnf` claim. The sub-credential is signed with `sk_U`
and carries `pk_S` in its own `cnf`. From there on, the agent wallet presents
like an ordinary holder: it signs a Key Binding JWT with `sk_S` over the
verifier's nonce and identity. Only the verifier sees the difference, because
it walks the whole chain.

The agent wallet and the verifier never talk to each other directly. The
agent relays between them. That is what makes the agent's compromise
interesting: it sits on the wire but holds no keys.

## Who checks what

Policy is enforced in three places, each catching a different failure:

1. **The user wallet, when delegating.** It sets the policy and hands over
   only the disclosures for delegated claims. Undelegated claims can't leak
   later, because the agent wallet never had them.
2. **The agent wallet, on every request.** It refuses anything outside the
   policy. It is the only component that is trusted, present at request time,
   and placed before disclosure, so it is the one that stops a prompt
   injection.
3. **The verifier, on every presentation.** It rejects anything outside the
   signed policy. This bounds the damage if the agent wallet itself is
   compromised.

The policy lives in the signed sub-credential, so verifiers can check it too.
That limits it to rules a verifier can check from a single presentation:
allowed claims, allowed audiences, expiry. Stateful rules such as rate limits
can't be checked from outside and are out of scope.

## Layout

```
crates/
  sd-jwt-9901/        RFC 9901 implementation. No wallet or MCP concepts.
  delegate-sd-jwt/    Sub-credential format and chain verification.
  agent-wallet/       Policy enforcement, presentation building, sk_S handling.
  agent-wallet-mcp/   MCP interface to the agent wallet. Thin on purpose.
  user-wallet/        CLI stand-in for the user's wallet. Holds sk_U.
  mock-issuer/        Mints credentials for the demo.
  mock-verifier/      The wine shop.
```

`sd-jwt-9901` is meant to stand alone and be publishable by itself. Don't let
wallet concepts leak into it. `delegate-sd-jwt` builds on it and is shared by
the user wallet, the agent wallet and the verifier.

The MCP interface is deliberately small: `find_credential` lists credential
types and claim names, never values, and `create_presentation` asks for a
presentation. No tool returns the credential, disclosures or keys, and no tool
delegates or issues anything. The interface holds no keys, so it sits outside
the trusted base: the agent wallet treats every call through it as coming from
the untrusted agent.

## Standards

- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) — Selective Disclosure
  for JWTs. Published November 2025.
- `draft-ietf-oauth-sd-jwt-vc-19` — credential format. Working group work is
  complete and it is headed for RFC status. Emit `dc+sd-jwt` as `typ`.
- [`draft-gco-oauth-delegate-sd-jwt-00`](https://datatracker.ietf.org/doc/draft-gco-oauth-delegate-sd-jwt/)
  — delegation from a Holder to a Delegate Holder. The sub-credential is the
  draft's Key Binding SD-JWT: the user's key binding on the ID credential is
  itself an SD-JWT, whose payload carries `pk_S` and the policy. In the draft's
  terms, the user wallet is the Holder and the agent wallet is the Delegate
  Holder.

## Building

```sh
cargo test --workspace   # builds and runs what exists; not much yet
```

## Out of scope

Zero-knowledge proofs, unlinkable presentations, delegation by agents (only
users sub-issue, and only one hop), and a real phone wallet. The user wallet is
a CLI standing in for the phone wallet a real deployment would use.

**Presentations are linkable.** Two verifiers who compare notes can tell they
saw the same credential: the issuer's signature, `pk_U` and `pk_S` are the
same in every presentation. The sub-credential's allowed audiences are
separately disclosable, so a verifier sees only its own entry, but it still
learns that it was reached through a delegation and when that delegation
expires. Unlinkability is future work, not a gap that was overlooked.

## Licence

MIT