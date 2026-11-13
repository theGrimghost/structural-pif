import unittest

from pif.firewall import ALL_LAYERS
from evals.cases import CASES
from evals.run import CONFIGS, all_cases, evaluate, validate


class TestEvalHarness(unittest.TestCase):
    def test_cases_are_valid_and_unique(self):
        validate(all_cases())

    def test_enough_cases(self):
        self.assertGreaterEqual(sum(c.kind == "attack" for c in CASES), 35)
        self.assertGreaterEqual(sum(c.kind == "benign" for c in CASES), 20)

    def test_every_config_runs_and_is_deterministic(self):
        for name, layers in CONFIGS.items():
            with self.subTest(config=name):
                a = [(r.blocked, r.reasons) for r in evaluate(all_cases(), layers)]
                b = [(r.blocked, r.reasons) for r in evaluate(all_cases(), layers)]
                self.assertEqual(a, b)

    def test_removing_a_layer_never_blocks_more(self):
        full = evaluate(all_cases(), ALL_LAYERS)
        for name, layers in CONFIGS.items():
            res = evaluate(all_cases(), layers)
            for r, f in zip(res, full):
                with self.subTest(config=name, case=r.case.id):
                    if r.blocked:
                        self.assertTrue(f.blocked)

    def test_structural_layers_each_matter(self):
        def stopped(layers):
            return sum(r.blocked for r in evaluate(all_cases(), layers) if r.case.kind == "attack")
        full = stopped(ALL_LAYERS)
        self.assertLess(stopped(CONFIGS["no_toolauth"]), full)
        self.assertLess(stopped(CONFIGS["no_egress"]), full)


if __name__ == "__main__":
    unittest.main()
