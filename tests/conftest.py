"""Pytest configuration and platform-specific utilities."""

import os
import tempfile

import pytest

if os.name == "nt":
    _ORIGINAL_NAMED_TEMPORARY_FILE = tempfile.NamedTemporaryFile

    class _WindowsFriendlyTempFile:
        """Wrapper that closes the backing file when its name is accessed."""

        def __init__(self, wrapped):
            self._wrapped = wrapped
            self._closed_for_delete = False

        def __getattr__(self, item):
            return getattr(self._wrapped, item)

        @property
        def name(self):
            if not self._closed_for_delete and not self._wrapped.closed:
                try:
                    self._wrapped.flush()
                except Exception:
                    pass
                self._wrapped.close()
                self._closed_for_delete = True
            return self._wrapped.name

        def __enter__(self):
            self._wrapped.__enter__()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return self._wrapped.__exit__(exc_type, exc_val, exc_tb)

    def _named_temporary_file(*args, **kwargs):
        wrapped = _ORIGINAL_NAMED_TEMPORARY_FILE(*args, **kwargs)
        return _WindowsFriendlyTempFile(wrapped)

    @pytest.fixture(autouse=True, scope="session")
    def _patch_named_temporary_file():
        tempfile.NamedTemporaryFile = _named_temporary_file
        try:
            yield
        finally:
            tempfile.NamedTemporaryFile = _ORIGINAL_NAMED_TEMPORARY_FILE
