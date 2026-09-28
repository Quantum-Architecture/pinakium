#!/usr/bin/env python3
from __future__ import annotations
"""Pinakium public verifier — checks a certificate + ownership chain offline. python pinakium_verify.py chain.json [artwork_file]
Exit 0 if VALID, 1 otherwise. Requires `cryptography`."""

import hashlib, json, time, uuid
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
def canon(x) -> str: return json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
def H(x) -> str: return hashlib.sha256(canon(x).encode()).hexdigest()
def pseudo(ref: str) -> str: return "P-" + hashlib.sha256(("pinakium|" + ref.strip().lower()).encode()).hexdigest()[:20]
@dataclass
class Party:
    name: str; key: Ed25519PrivateKey
    @classmethod
    def new(cls, name): return cls(name, Ed25519PrivateKey.generate())
    @property
    def pub(self) -> str: return self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    def sign(self, body: dict) -> str: return self.key.sign(canon(body).encode()).hex()
def _ok(pub: str, body: dict, sig: str) -> bool:
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), canon(body).encode()); return True
    except Exception: return False
def verify_chain(chain: list[dict], trusted_artists: set[str] | None = None, image_bytes: bytes | None = None) -> dict:
    """Vérification hors ligne, par n'importe qui : signatures, continuité, acceptations, image, propriétaire courant."""
    if not chain or chain[0]["body"].get("type") != "AUTHENTICITY": return {"valid": False, "reason": "certificat d'authenticité manquant"}
    coa = chain[0]; b = coa["body"]
    if not _ok(b["artist_pub"], b, coa["sig"]): return {"valid": False, "reason": "signature de l'artiste invalide"}
    if trusted_artists is not None and b["artist_pub"] not in trusted_artists: return {"valid": False, "reason": "artiste non reconnu"}
    if image_bytes is not None and hashlib.sha256(image_bytes).hexdigest() != b["image_sha256"]: return {"valid": False, "reason": "l'image ne correspond pas au certificat"}
    owner_pub, prev = b["artist_pub"], coa
    for n, link in enumerate(chain[1:], 1):
        lb = link["body"]
        if lb.get("work_id") != b["work_id"] or lb.get("prev") != H({"body": prev["body"], "sig": prev["sig"]}): return {"valid": False, "reason": f"maillon {n} : continuité rompue"}
        if lb["from_pub"] != owner_pub: return {"valid": False, "reason": f"maillon {n} : cédé par quelqu'un qui n'était pas propriétaire"}
        if not _ok(lb["from_pub"], lb, link["sig"]): return {"valid": False, "reason": f"maillon {n} : signature du cédant invalide"}
        if not link.get("accept_sig") or not _ok(lb["to_pub"], {"accept": H({"body": lb, "sig": link["sig"]})}, link["accept_sig"]): return {"valid": False, "reason": f"maillon {n} : acceptation du nouveau propriétaire absente ou invalide"}
        owner_pub, prev = lb["to_pub"], link
    return {"valid": True, "work_id": b["work_id"], "title": b["work"].get("title"), "artist": b["artist"], "owners": len(chain) - 1, "current_owner_pub": owner_pub}
def detect_fork(links: list[dict]) -> list[str]:
    """Double cession : deux maillons signés qui partent du même précédent."""
    seen, forks = {}, []
    for l in links:
        p = l["body"]["prev"]
        if p in seen: forks.append(p)
        seen[p] = True
    return forks

if __name__ == "__main__":
    import sys
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            chain = json.load(f)
        if len(sys.argv) > 2:
            with open(sys.argv[2], "rb") as f:
                img = f.read()
        else:
            img = None
        r = verify_chain(chain, image_bytes=img); forks = detect_fork(chain[1:])
    except (KeyError, TypeError, ValueError, IndexError, OSError, json.JSONDecodeError) as e:
        print(f"INVALID  malformed input ({type(e).__name__})"); sys.exit(1)
    print(("VALID  " if r["valid"] and not forks else "INVALID  ") + json.dumps(r, ensure_ascii=False) + (f"  double-sale forks: {forks}" if forks else "")); sys.exit(0 if r["valid"] and not forks else 1)
