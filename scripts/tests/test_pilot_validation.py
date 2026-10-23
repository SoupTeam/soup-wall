import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "qualify-prepared-pilot-run.py"


class ValidationDeadlineTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location("validation_driver", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_validation_budget_is_finite_and_keeps_existing_default(self):
        driver = self.load()
        self.assertTrue(hasattr(driver, "validation_timeout"), "bounded validation budget is missing")
        self.assertEqual(driver.validation_timeout(SimpleNamespace()), 30)
        self.assertEqual(driver.validation_timeout(SimpleNamespace(validation_timeout_seconds=120)), 120)
        for value in (0, -1, 181, float("inf"), float("nan"), True, "120"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                driver.validation_timeout(SimpleNamespace(validation_timeout_seconds=value))


if __name__ == "__main__":
    unittest.main()
