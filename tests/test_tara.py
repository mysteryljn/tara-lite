import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tara import analyze, main

class TaraTests(unittest.TestCase):
    def test_sorted_risk(self):
        results=analyze({"threats":[{"id":"low","asset":"x","severity":1,"likelihood":1},{"id":"high","asset":"y","severity":5,"likelihood":4}]})
        self.assertEqual(results[0]["id"],"high"); self.assertEqual(results[0]["risk"],"CRITICAL")

    def test_fractional_risk_inputs_are_rejected_instead_of_truncated(self):
        with self.assertRaisesRegex(ValueError, "severity must be an integer 1..5"):
            analyze({"threats":[{"id":"fractional","asset":"x","severity":4.9,"likelihood":5}]})

    def test_missing_fields_error_is_reported(self):
        with self.assertRaisesRegex(ValueError, r"threats\[0\] missing asset, likelihood"):
            analyze({"threats":[{"id":"T-001","severity":3}]})

    def test_duplicate_threat_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, r"threats\[1\] duplicate id 'T-001'"):
            analyze({"threats":[
                {"id":"T-001","asset":"gateway","severity":5,"likelihood":5},
                {"id":"T-001","asset":"ota","severity":4,"likelihood":5},
            ]})

    def test_threat_ids_must_be_non_empty_strings(self):
        base = {"asset": "gateway", "severity": 5, "likelihood": 5}
        for invalid_id in (None, 1, [], ""):
            with self.subTest(invalid_id=invalid_id):
                with self.assertRaisesRegex(ValueError, r"threats\[0\] id must be a non-empty string"):
                    analyze({"threats": [{**base, "id": invalid_id}]})

    def test_mixed_id_types_are_reported_as_input_errors(self):
        with self.assertRaisesRegex(ValueError, r"threats\[1\] id must be a non-empty string"):
            analyze({"threats": [
                {"id": "T-001", "asset": "gateway", "severity": 1, "likelihood": 1},
                {"id": 2, "asset": "ota", "severity": 1, "likelihood": 1},
            ]})

    def test_malformed_model_shape_is_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, "model must be an object"):
            analyze([])
        with self.assertRaisesRegex(ValueError, "threats must be an array"):
            analyze({"threats": {"id": "T-001"}})
        with self.assertRaisesRegex(ValueError, r"threats\[0\] must be an object"):
            analyze({"threats": ["T-001"]})

    def test_output_write_errors_are_reported_as_cli_errors(self):
        with TemporaryDirectory() as temporary_directory:
            model_path = Path(temporary_directory) / "model.json"
            model_path.write_text(
                '{"threats": [{"id": "T-001", "asset": "gateway", "severity": 5, "likelihood": 5}]}',
                encoding="utf-8",
            )
            output_path = Path(temporary_directory) / "missing" / "results.json"
            with patch("builtins.print") as print_mock:
                exit_code = main([str(model_path), "--output", str(output_path)])

            self.assertEqual(exit_code, 2)
            print_mock.assert_called_once()
            self.assertTrue(print_mock.call_args[0][0].startswith("error: "))

if __name__=="__main__": unittest.main()
