import unittest

from benchshield.benchdata import generate_tasks, public_view, solve


class TestBenchData(unittest.TestCase):
    def test_count_and_determinism(self):
        a = generate_tasks(50, seed=42)
        b = generate_tasks(50, seed=42)
        self.assertEqual(len(a), 50)
        self.assertEqual(a, b)

    def test_gold_answers_are_correct(self):
        for task in generate_tasks(50, seed=7):
            self.assertEqual(task["gold"], solve(task["category"], task["params"]))

    def test_all_categories_present(self):
        tasks = generate_tasks(50, seed=42)
        cats = {t["category"] for t in tasks}
        self.assertEqual(len(cats), 5)

    def test_public_view_hides_gold(self):
        task = generate_tasks(1, seed=1)[0]
        view = public_view(task)
        self.assertNotIn("gold", view)
        self.assertEqual(view["prompt"], task["prompt"])


if __name__ == "__main__":
    unittest.main()
