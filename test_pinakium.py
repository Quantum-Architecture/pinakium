import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
V = os.path.join(HERE, "tools", "pinakium_verify.py")
EX = os.path.join(HERE, "examples")


def run(*a):
    return subprocess.run([sys.executable, V, *a], capture_output=True, text=True)


class TestPinakium(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, os.path.join(HERE, "tools", "make_examples.py")], check=True, capture_output=True)

    def test_valid_chain_with_image(self):
        p = run(os.path.join(EX, "chain_example.json"), os.path.join(EX, "artwork_demo.bin"))
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn('"owners": 2', p.stdout)

    def test_wrong_image_refused(self):
        f = tempfile.NamedTemporaryFile(delete=False); f.write(b"other bytes"); f.close()
        self.assertEqual(run(os.path.join(EX, "chain_example.json"), f.name).returncode, 1)

    def test_tampered_wrong_owner_and_fork_refused(self):
        for n in ("chain_tampered.json", "chain_wrong_owner.json", "chain_fork.json"):
            self.assertEqual(run(os.path.join(EX, n)).returncode, 1, n)

    def test_missing_acceptance_refused(self):
        with open(os.path.join(EX, "chain_example.json"), encoding="utf-8") as src:
            c = json.load(src)
        del c[1]["accept_sig"]
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(c, f); f.close()
        p = run(f.name)
        self.assertEqual(p.returncode, 1)
        self.assertIn("acceptation", p.stdout)

    def test_malformed_inputs_do_not_crash(self):
        for content in ("[]", "{}", '[{"body": {"type": "AUTHENTICITY"}}]', "not json"):
            f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); f.write(content); f.close()
            p = run(f.name)
            self.assertEqual(p.returncode, 1, content)
            self.assertNotIn("Traceback", p.stderr, content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
