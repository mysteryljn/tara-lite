import unittest
from tara import analyze

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

    def test_malformed_model_shape_is_rejected_with_value_error(self):
        with self.assertRaisesRegex(ValueError, "model must be an object"):
            analyze([])
        with self.assertRaisesRegex(ValueError, "threats must be an array"):
            analyze({"threats": {"id": "T-001"}})
        with self.assertRaisesRegex(ValueError, r"threats\[0\] must be an object"):
            analyze({"threats": ["T-001"]})

if __name__=="__main__": unittest.main()
