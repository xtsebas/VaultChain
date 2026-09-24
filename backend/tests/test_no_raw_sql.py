"""
Regression test for SQL Injection: enforces that the backend only talks to
the database through Django's parameterized ORM, never through raw/concatenated
SQL (.raw(), cursor.execute(), connection.cursor(), or extra()).

If this test ever fails, someone introduced a raw SQL query — that code must
be reviewed for injection risk (parameterized placeholders, no string
formatting/concatenation of user input) before being merged.
"""
import os
import re
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXCLUDED_DIR_NAMES = {'migrations', 'tests', 'venv', '.venv', 'node_modules'}

FORBIDDEN_PATTERNS = [
    re.compile(r'\.raw\('),
    re.compile(r'cursor\.execute\('),
    re.compile(r'connection\.cursor\('),
    re.compile(r'\.extra\('),
]


def _python_files():
    for root, dirs, files in os.walk(BACKEND_DIR):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIR_NAMES and not d.startswith('.')]
        for name in files:
            if name.endswith('.py'):
                yield os.path.join(root, name)


class NoRawSqlTest(unittest.TestCase):
    def test_no_raw_or_unparameterized_sql_in_backend(self):
        offenders = []
        for path in _python_files():
            with open(path, encoding='utf-8') as f:
                content = f.read()
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(content):
                    offenders.append((os.path.relpath(path, BACKEND_DIR), pattern.pattern))

        self.assertEqual(
            offenders,
            [],
            'Raw/unparameterized SQL usage found (use the Django ORM instead): '
            f'{offenders}',
        )


if __name__ == '__main__':
    unittest.main()
