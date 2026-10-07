# Test vectors

`ML_DSA_44.jose.json` and `ML_DSA_65.jose.json` are the JOSE examples from
`draft-ietf-cose-dilithium`, copied unchanged from
https://github.com/cose-wg/draft-ietf-cose-dilithium/tree/main/examples/jose/examples
at commit `1bd8f37`.

Each holds a seed (`priv`), the public JWK derived from it, and a compact JWS
signed with the deterministic variant of ML-DSA and an empty context string.