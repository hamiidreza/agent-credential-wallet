# Design notes

Decisions that are settled, and the reasoning behind them.

Terms — issuer, user wallet, agent, agent wallet, verifier, sub-credential —
are as defined in the README.

## Keys

| Key | Held by | Job | Frequency | Protection |
|---|---|---|---|---|
| Issuer | Issuer | Signs the ID credential | Often | SoftHSM via PKCS#11 |
| `sk_U` (user root) | User wallet | Proof of possession at issuance; signs sub-credentials | Rarely, user present | Software file, encrypted at rest |
| `sk_S` (agent wallet key) | Agent wallet | Signs presentations | Constantly, unattended | Software file |

All three are ML-DSA-44. The system is post-quantum end to end. `pk_U` goes in
the ID credential's `cnf` claim and `pk_S` in the sub-credential's. The agent
holds no key.

**The agent wallet never has access to `sk_U`.** If it did, a compromised
agent wallet could sign itself a new sub-credential with any policy, and
delegation would bound nothing. In a deployment the separation is physical:
`sk_U` on the user's phone, `sk_S` on the server next to the agent. Here,
`sk_U` lives only in the user-wallet CLI, encrypted with a passphrase the agent
wallet never sees.

**Why software is enough for `sk_S`.** The sub-credential bounds the damage. A
stolen `sk_S` allows presentations of the delegated claims to the delegated
audiences until the sub-credential expires. It cannot reveal undelegated
claims, because the agent wallet never had them, and it cannot widen its own
policy, because that needs `sk_U`. It does not allow permanent impersonation.

**Why `sk_U` is software here.** The user wallet is a CLI stand-in for a phone
wallet, so `sk_U` is a file. On a phone it would live in secure hardware, with
a biometric check on every signature. The state of that hardware is a finding
worth reporting. As of iOS 26 the Secure Enclave holds ML-DSA keys, but only
ML-DSA-65 and ML-DSA-87, not 44. Commodity security keys such as YubiKey had
only prototypes at the time of writing. PQ migration at the edge is constrained
by which parameter sets each class of device offers, not only by whether it
supports ML-DSA at all.

**Mixed parameter sets are allowed.** A phone-based user wallet would sign
sub-credentials with ML-DSA-65 while the issuer and `sk_S` stay on 44. Each
signature names its own `alg`, so the verifier handles a mixed chain without
special cases. The test suite includes one.

## Sub-credentials

Follows `draft-gco-oauth-delegate-sd-jwt-00`. The sub-credential is not a
separate artifact; it *is* the KB-JWT of the ID credential, made selectively
disclosable in its own right and signed with `sk_U`. One chained wire format:

```
<SD-JWT>~~<KB-SD-JWT>~<KB-JWT>
```

Verification walks the chain: the issuer's key verifies the first link, and the
`cnf` claim of each link supplies the key for the next.

### The policy lives in the sub-credential

Every rule the agent wallet enforces is in the signed sub-credential, so
verifiers can check it too. That limits the policy to rules a verifier can
check from a single presentation: which audience, which claims for that
audience, and until when. Stateful rules such as rate limits or spending caps
cannot be checked from outside, so they are out of scope, and there is no
separate local policy file.

### Audience scope: one delegate payload per audience

Sub-credentials carry per-audience scope in `delegate_payload`, one payload per
audience, each with its own `aud`, claim allow-list and `exp`. The agent wallet
discloses the one matching the verifier in front of it, so the wine shop does
not learn the pharmacy was also authorized.

The simpler alternative is a single payload with a disclosable `aud` array,
which hides the other audiences equally well. It was not chosen because every
audience would then share one allow-list and one `exp`. Per-audience scoping is
what lets the wine shop be limited to `over_18` while another verifier gets
more.

One `sk_U` signature covers the whole set, which matters because `sk_U` signs
only with the user present.

This is also what makes software storage for `sk_S` defensible: the audience
restriction is signed by the user and checked by the verifier, not merely
enforced by a policy sitting next to the stolen key.

### Only delegated disclosures are handed over

The user wallet hands the agent wallet the issuer-signed JWT and only the
disclosures for claims that appear in at least one allow-list. A claim outside
every allow-list could never pass a verifier's check, so handing it over would
only add something to leak. Undelegated claims cannot leak later, even from a
compromised agent wallet, because it never had them.

### Binding is `issuer_jwt_hash`, not `sd_hash`

`sd_hash` covers the preceding SD-JWT *and its disclosures*, freezing the
disclosure set at delegation time: every presentation would have to reveal
every delegated claim, to every verifier. `issuer_jwt_hash` covers only the
issuer-signed JWT, so the agent wallet can disclose, per verifier, just the
claims that verifier's allow-list permits and the request asks for.

Per-audience allow-lists depend on this. With `sd_hash`, the wine shop would
see the pharmacy's claims too.

### The final KB-JWT is where `sk_S` does its work

The last component of the chain is an ordinary KB-JWT, signed by `sk_S`, freshly
per request. It covers the verifier's nonce, the verifier's identity, and an
`sd_hash` over the sub-credential and its disclosures, as the draft specifies.

The nonce and the audience binding defend against different things. The nonce
stops replay: a presentation captured off the wire cannot be sent again,
because the next request carries a different nonce. The audience binding stops
the wine shop from taking a presentation it legitimately received and reusing
it against the pharmacy.

## The MCP interface

The agent wallet is exposed through an MCP interface; it is not itself an MCP
server. MCP carries messages, and the wallet provides the security.

The interface is outside the trusted base. It holds no keys, so it cannot forge
anything. It can alter requests or leak presentations, but a compromised agent
can already do both. The agent wallet therefore treats every call through it
as coming from the untrusted agent, and the two run as separate processes so
that this holds literally.

The tool list is the attack surface, so it has two tools: `find_credential`
(credential types and claim names, never values) and `create_presentation`.
No tool returns the credential, disclosures or keys, and none delegates or
issues anything. Sub-credentials are issued by the user wallet, never through
MCP.

## Decisions log

Small choices with no other natural home.

- **Only users delegate, and only one hop.** The draft allows a delegate holder
  to delegate further. That would need attenuation rules checked at every link,
  and a delegation tool would let an injected agent hand its authority to a
  wallet the attacker controls.
- **No revocation of sub-credentials; short `exp` instead.** The same trade the
  draft makes: a user cannot easily distribute revocation information to
  verifiers.
- **Rust edition 2024, no declared MSRV.** The post-quantum crates move fast
  and promising an old compiler would only get in the way. CI tracks stable.
- **`unsafe_code = "forbid"` workspace-wide.** The PKCS#11 work in section G
  goes through `cryptoki`, which holds the unsafe FFI on its side. If that
  turns out to be wrong, soften to `deny` and allow it at the one site that
  needs it.