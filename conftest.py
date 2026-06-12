# conftest.py
"""
pytest configuration — ensures the project root is on sys.path
so that `from app.xxx import ...` works without installing the package.
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))
