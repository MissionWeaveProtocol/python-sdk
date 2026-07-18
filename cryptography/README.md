# Signed-document cryptography vectors

`manifest.json` defines the protocol-owned MissionWeaveProtocol 0.1 cryptography bundle for the
Signed Document Verification Profile in Section 6.4 of the specification. It covers all nine
signature-required schema profiles with 22 cases: four expected-accept cases and eighteen
expected-reject cases. The all-profile case evaluates one document for each profile, and the
failure-matrix cases cover multiple isolated faults without increasing the 22-case contract. The
suite therefore contains 58 evaluations in total: 12 expected to complete and 46 expected to be
rejected.

The nine schema profiles are Agent Card, Approval, Artifact manifest, Command, Context Package,
Event, Evidence, Extension Profile, and Group Snapshot. Every signed-document evaluation
identifies its profile, input document, Registry fixture, expected semantic stage, and expected
wire error independently. A successful signed-document evaluation also fixes the canonical
signing bytes, signing hash, resolved key and Principal, protected signed time, and Ed25519
signature. The separate RFC 8785 canonicalization evaluation fixes the official input, canonical
bytes, and SHA-256 hash. Digest-protected timestamp-profile coverage accepts a lowercase `t` with
an uppercase protected `Z`, lowercase Registry `t`/`z`, the RFC 3339 numerical-offset endpoints
`-23:59` and `+23:59`, and fractional-second ordering decided only after the sixth digit. It also
requires leap-second, year-`0000`, and `-00:00` spellings to fail first at schema stage when they
occur in a Schema-declared Signed Document timestamp.

Strict Ed25519 coverage rejects identity, non-identity small-order, mixed-order, off-curve,
negative-zero, and noncanonical public-key encodings at key resolution. Signature-envelope
coverage independently rejects off-curve, negative-zero, non-identity small-order, mixed-order,
and noncanonical `R` encodings, including the exact `y = p` canonical boundary, and rejects
`S = L`; identity `R` remains permitted and is exercised through the final signature equation.

The semantic verification stages are:

1. strict UTF-8 JSON parsing;
2. normative JSON Schema validation;
3. signature-envelope and protected-time validation;
4. signing-key resolution and validity validation;
5. RFC 8785 canonicalization and signing-hash production; and
6. Ed25519 signature verification.

`complete` is the successful outcome after all six stages. Reject evaluations isolate one intended
fault and identify the first normative stage at which verification must stop.

Passing this bundle demonstrates conformance to its declared evaluations across the six
cryptographic verification stages above. It does **not** prove First-Admission Record validation,
historical-trust validation, Command freshness or clock-skew enforcement, or signer authorization
under applicable role and policy. Those checks remain separate normative requirements in the
protocol specification.

The `artifactDigest` in `manifest.json` binds the manifest's semantic content and every declared
key, schema, canonicalization artifact, and signed-document vector. Implementations should pin a
protocol release or commit together with this digest and run every declared evaluation without
network access.

To calculate `artifactDigest`, remove exactly the top-level `artifactDigest` member from the parsed
manifest, serialize the remaining manifest with RFC 8785 JCS, hash those canonical bytes with
SHA-256, and encode the result as `sha256:` followed by 64 lower-case hexadecimal digits. Each
entry in `artifacts` separately hashes the exact file bytes named by `path`; those entries make the
top-level digest transitively bind every declared artifact.

The manifest's `fixtureSchemas` object names language-neutral JSON Schemas for Registry fixtures
and test-only signing-key fixtures. An implementation MUST validate fixture structure against the
named Schema before evaluating a case. The Registry fixture Schema intentionally describes the
container shape rather than asserting that every binding is semantically valid: negative cases
depend on structurally readable values that stages 3 or 4 must reject. Implementations MUST still
apply every semantic check in the declared order and MUST NOT normalize an invalid fixture into a
valid value.

The files under `keys/` are deterministic, test-only fixtures. The signing-key fixtures expose test
seeds so implementations can reproduce the positive signing cases; they MUST NOT be used outside
conformance testing.

Regenerate the committed artifacts deterministically and require a zero diff:

```bash
python scripts/generate_crypto_vectors.py
git status --porcelain=v1 --untracked-files=all -- \
  cryptography/manifest.json cryptography/keys cryptography/vectors \
  > /tmp/generated-artifact-status
sed -n '1,200p' /tmp/generated-artifact-status
test ! -s /tmp/generated-artifact-status
```

`requirements-cryptography.txt` declares the direct validator dependencies. The committed
`requirements-cryptography.lock` pins the complete Python 3.12.13 dependency graph and every
accepted distribution hash. Its header records the exact `uv` version, resolution cutoff, and
compile command used by CI; regenerating it MUST produce a zero diff.

Run the protocol-owned validator locally from the hash-locked environment with:

```bash
uv venv --python 3.12.13 .venv-cryptography
uv pip install --python .venv-cryptography/bin/python --require-hashes --no-deps \
  --only-binary :all: --strict --requirements requirements-cryptography.lock
.venv-cryptography/bin/python scripts/validate_crypto_vectors.py
```
