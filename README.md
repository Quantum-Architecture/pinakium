# Pinakium — public verifier & proofs
**The certified studio and collection.** Pinakium issues artist-signed certificates of authenticity and an ownership chain that nobody can rewrite. This repository publishes the **verifier**: anyone can check a chain, free, offline, without Pinakium.

## Verify a chain yourself
```
pip install cryptography
python tools/pinakium_verify.py examples/chain_example.json examples/artwork_demo.bin   # VALID
python tools/pinakium_verify.py examples/chain_tampered.json                            # INVALID — signature does not match
python tools/pinakium_verify.py examples/chain_wrong_owner.json                          # INVALID — transferred by someone who was not the owner
```
`examples/dossier/dossier.html` shows the printable collection file a buyer receives.

## What a VALID result guarantees
- the certificate is signed by the artist's key and bound to the exact image (SHA-256);
- every transfer is signed by the owner of record **and accepted** by the new owner; a double sale creates a detectable fork;
- buyer identities are pseudonymised — no name or e-mail appears in the chain.

## What it does not guarantee
The graded classification (human / digital / hybrid / AI) is **indicative**: it rests on the evidence the artist provides. A certificate proves who signed it and that nothing changed since — not the quality, value or originality of the work. This is not a legal timestamp.

## Quality evidence
13 automated tests in the product (full artist → buyer path, image mismatch, non-owner transfer refused, acceptance required, double sale detected, pseudonymisation, quotas per licence period, service end-to-end). Product and plans: [Pinakium](https://quantumexcellium.com/pinakium).
