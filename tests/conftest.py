import pytest

from core.cheatsheet import cheat_sheet_manager


@pytest.fixture(autouse=True)
def _reset_cheat_sheet():
    cheat_sheet_manager.load_default()
    yield
    cheat_sheet_manager.load_default()
