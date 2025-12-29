import random
import unittest
from streamlit_app import clean_names, validate_names, generate_single_cycle, pairs_to_map, validaSorteio

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
        self.assertIn("mínimo de 3", msg.lower())

    def _assert_single_cycle(self, names):
        pairs = generate_single_cycle(names)
        mapa = pairs_to_map(pairs)
        valido, msg = validaSorteio(mapa)
        self.assertTrue(valido, msg)
        self.assertEqual(len(mapa), len(names))

    def test_ciclos_pequenos(self):
        self._assert_single_cycle(["Ana", "Bruno", "Carla"])
        self._assert_single_cycle(["Ana", "Bruno", "Carla", "Diego"])

    def test_ciclo_maior(self):
        nomes = [f"P{i}" for i in range(10)]
        self._assert_single_cycle(nomes)

    def test_propriedade_sem_2_ciclos(self):
        nomes = ["A", "B", "C", "D", "E", "F"]
        for seed in range(50):
            random.seed(seed)
            self._assert_single_cycle(nomes)

if __name__ == "__main__":
    unittest.main()
