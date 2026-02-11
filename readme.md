# the Hofmann Elimination

## Purpose

This project provides a protocol to create consistent,
reusable identifiers across multiple clients without sharing the
key data used to make up that identifier. This results in an identifier that can
be used with services without those services knowing the origins of the data used.
Useful when that data is based on information one does not want to expose
outside of the owning client. This implements the Oblivious Pseudorandom Function (OPRF)
protocol, specifically **RFC 9497 OPRF(P-256, SHA-256) mode 0**, using
RFC 9380 hash-to-curve techniques to achieve this goal.

# Protocol

The protocol relies on the following data types:
- `P`: A point on P-256 derived from the input text using RFC 9497 HashToGroup.
- `r`: A random blinding factor chosen by the client to ensure that the blinded point `Q` is different for each submission, even for the same input.
- `Q`: The blinded point computed by the client as `Q = P · r`.
- `s`: A master secret key held by the service (skS).
- `R`: The blinded (ec point) result computed by the service as `R = Q · s = P · r · s`.
- `N`: The unblinded (ec point) result computed by the client as `N = r⁻¹ · R = s·P`.

The protocol flow is as follows:

```
Client                          Service
────────                        ───────
1. P = HashToGroup(input)
2. Q = P · r
3. Send Q  ─────────────────►   R = Q · s
           ◄─────────────────   R = P · r · s
4. N = R · r⁻¹ = P · s
5. identityKey = SHA-256(I2OSP(len(input),2) || input || I2OSP(33,2) || SerializeElement(N) || "Finalize")
```

## Cipher Suite: RFC 9497 P256-SHA256 (mode 0)

- **contextString**: `OPRFV1-\x00-P256-SHA256`
- **HashToGroup DST**: `HashToGroup-OPRFV1-\x00-P256-SHA256`
- **HashToScalar DST**: `HashToScalar-OPRFV1-\x00-P256-SHA256`
- **HashToGroup**: RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` (direct Simplified SWU, no isogeny)
- **Finalize**: `SHA-256(I2OSP(len(input),2) || input || I2OSP(33,2) || compressed_N || "Finalize")`
- **Key derivation**: RFC 9497 `DeriveKeyPair(seed, info)` using `HashToScalar` with counter

## Details for each step

1. The client takes the input text (UTF-8 bytes) and applies RFC 9497 HashToGroup to derive a point `P` on P-256.
2. The client computes the blinded point `Q` by multiplying `P` with a random blinding factor `r`.
3. The client sends the blinded point `Q` to the service. The service computes `R` by multiplying `Q` with the master key `s`. This results in `R = s · P · r`.
4. The client receives `R` and unblinds it by multiplying with the inverse of the blinding factor `r`, yielding `N = s·P`.
5. Finally, the client derives a consistent identity key using the RFC 9497 Finalize function.

## Useful classes

- `Client` : Shows in detail what the client is doing for the protocol. See `convertToIdentityKey()` for the main workflow.
- `Server` : The API requirements for a basic system to allow for clients to create new keys.
- `ServerImpl` : Naive implementation that implements the protocol in a basic way.
- `Curve` : Default behavior needed from any Curve implementation. Uses Bouncy Castle as that should be C# compatible.
- `OprfSuite` : RFC 9497 P256-SHA256 cipher suite constants and algorithms.
- `RoundTripTest` : Examples of how it works and to verify the code is sound.
- `OprfVectorsTest` : RFC 9497 Appendix A test vectors for P256-SHA256 OPRF mode.

# References

## OPAQUE / aPAKE
The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) protocol is a primary
inspiration for this project. OPAQUE allows two parties to cooperate to securely compute
a pseudorandom function over an insecure channel without revealing the input to the other party.
- [Original Paper](https://eprint.iacr.org/2018/163.pdf)
- [Password-authenticated key exchange - Wikipedia](https://en.wikipedia.org/wiki/Password-authenticated_key_exchange)
- [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html)

## OPRF
Oblivious Pseudorandom Function (OPRF) is a cryptographic mechanism that allows
one party (the client) to compute a pseudorandom function on an input without
revealing the input to the other party (the server). The server holds a secret
key that is used to compute the pseudorandom function, but it does not learn
anything about the client's input. This is used for things like secure multi-party computation.
- [Oblivious Pseudorandom Function - Wikipedia](https://en.wikipedia.org/wiki/Oblivious_pseudorandom_function)
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)

## Hash-to-Curve
Hash-to-curve is a technique used in elliptic curve cryptography to map arbitrary
input data (such as a string) to a point on an elliptic curve.
Protocols like OPRF use this technique to derive a point on the curve from the
input text. The hash-to-curve process ensures that the resulting point is
uniformly distributed on the curve. That uniform distribution is needed for security applications.

Implements the [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html) specification,
validated against the RFC's own test vectors (Appendix J.7.1 for secp256k1 and Appendix A.1.1 for P-256).

## Origins of the name

The [Hofmann Elimination](https://en.wikipedia.org/wiki/Hofmann_elimination) is a chemical reaction that involves the elimination of an
amine to produce an alkene. This reaction is named after the German chemist August
Wilhelm von Hofmann, who first described it in the 19th century. The Hofmann elimination
is often used to synthesize alkenes from amines. It does this by treating the quaternary
ammonium salt with a strong base, such as sodium hydroxide, which leads to the elimination
of the ammonium group and the formation of an alkene. The reaction is typically carried out
under heat to facilitate the elimination process.

Unlike other elimination reactions, the Hofmann elimination produces the least substituted
alkene as the major product, which is a result of the steric hindrance around the quaternary
ammonium salt. This makes it a useful reaction for synthesizing specific alkenes that may be
difficult to obtain through other methods.
