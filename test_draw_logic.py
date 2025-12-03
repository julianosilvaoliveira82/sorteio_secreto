import unittest
from streamlit_app import clean_names, validate_names, generate_derangement

class TestDrawLogic(unittest.TestCase):
    def test_clean_names(self):
        # Test cleaning
        input_text = "  maria   silva  \nJOÃO  \n  pedro"
        expected = ["Maria Silva", "João", "Pedro"]
        self.assertEqual(clean_names(input_text), expected)

    def test_validate_names(self):
        # Valid case
        valid, msg = validate_names(["A", "B", "C"])
        self.assertTrue(valid)

        # Duplicate case
        valid, msg = validate_names(["A", "B", "A"])
        self.assertFalse(valid)
        self.assertIn("duplicados", msg.lower())

        # Too few
        valid, msg = validate_names(["A", "B"])
        self.assertFalse(valid)
        self.assertIn("pelo menos 3", msg.lower())

    def test_derangement(self):
        # Test 100 times to ensure robustness
        names = ["A", "B", "C", "D"]
        for _ in range(100):
            result = generate_derangement(names)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), len(names))

            # Check 1: No self-draw
            for i, name in enumerate(names):
                self.assertNotEqual(name, result[i])

            # Check 2: All drawn (set equality)
            self.assertEqual(set(names), set(result))

if __name__ == "__main__":
    unittest.main()
