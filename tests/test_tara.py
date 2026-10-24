import unittest
from tara import analyze

class TaraTests(unittest.TestCase):
    def test_sorted_risk(self):
        results=analyze({"threats":[{"id":"low","asset":"x","severity":1,"likelihood":1},{"id":"high","asset":"y","severity":5,"likelihood":4}]})
        self.assertEqual(results[0]["id"],"high"); self.assertEqual(results[0]["risk"],"CRITICAL")
if __name__=="__main__": unittest.main()
