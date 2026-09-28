#!/usr/bin/env python3
"""Regenerates examples/ with DEMO keys (artist, owner 1, owner 2, attacker) — never production keys.
Files: chain_example.json (VALID) · chain_tampered.json · chain_wrong_owner.json · chain_fork.json (double sale) · artwork_demo.bin"""
import hashlib, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pinakium_verify import H, Party, canon  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples")
os.makedirs(OUT, exist_ok=True)
artist, o1, o2, attacker = Party.new("Demo Artist"), Party.new("Owner 1"), Party.new("Owner 2"), Party.new("Attacker")
img = b"demo artwork bytes v1\n"
with open(os.path.join(OUT, "artwork_demo.bin"), "wb") as f:
    f.write(img)
coa_body = {"type": "AUTHENTICITY", "work_id": "PK-DEMO-0001", "work": {"title": "Demo Work n° 1", "medium": "photography", "date": "2026"},
            "image_sha256": hashlib.sha256(img).hexdigest(), "artist": "Demo Artist", "artist_pub": artist.pub,
            "grading": {"classification": "human", "label": "Human-made", "confidence": "0.9"},   # strings, never floats
            "issued_at": 1790412252, "notice": "Demo certificate — DEMO KEYS, not a real work."}
coa = {"body": coa_body, "sig": artist.sign(coa_body)}


def transfer(prev, frm, to, ts):
    body = {"type": "TRANSFER", "work_id": "PK-DEMO-0001", "prev": H({"body": prev["body"], "sig": prev["sig"]}), "from_pub": frm.pub, "to_pub": to.pub, "at": ts}
    link = {"body": body, "sig": frm.sign(body)}
    link["accept_sig"] = to.sign({"accept": H({"body": body, "sig": link["sig"]})})
    return link


l1 = transfer(coa, artist, o1, 1790500000)
l2 = transfer(l1, o1, o2, 1790600000)
chain = [coa, l1, l2]
with open(os.path.join(OUT, "chain_example.json"), "w", encoding="utf-8") as out:
    json.dump(chain, out, indent=1, ensure_ascii=False)
t = json.loads(json.dumps(chain)); t[1]["body"]["at"] = 1790500001          # altered field, signature untouched
with open(os.path.join(OUT, "chain_tampered.json"), "w", encoding="utf-8") as out:
    json.dump(t, out, indent=1, ensure_ascii=False)
w = [coa, l1, transfer(l1, attacker, o2, 1790600000)]                         # sold by someone who never owned it
with open(os.path.join(OUT, "chain_wrong_owner.json"), "w", encoding="utf-8") as out:
    json.dump(w, out, indent=1, ensure_ascii=False)
f = [coa, l1, transfer(l1, o1, o2, 1790600000), transfer(l1, o1, attacker, 1790600001)]   # double sale from the same link
with open(os.path.join(OUT, "chain_fork.json"), "w", encoding="utf-8") as out:
    json.dump(f, out, indent=1, ensure_ascii=False)
print("examples regenerated (demo keys discarded)")
