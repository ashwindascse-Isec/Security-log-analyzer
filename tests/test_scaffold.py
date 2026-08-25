import importlib

def test_imports():
    modules = [
        "logrelay_engine",
        "logrelay_engine.schema",
        "logrelay_engine.storage",
        "logrelay_engine.indexing",
        "logrelay_engine.query",
    ]
    for mod in modules:
        imported = importlib.import_module(mod)
        assert imported is not None