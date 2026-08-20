import unittest

import app


class AppTests(unittest.TestCase):
    def test_ok(self):
        self.assertTrue(app.ok())
