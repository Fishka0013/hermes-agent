"""Shared fixtures for tests/hermes_state."""
import pytest


@pytest.fixture
def worker(tmp_path):
    """A registered compute worker execution on session ``owned``: ``(db, RuntimeSessionStore)``."""
    # Imported here, not at module level: this conftest loads for every hermes_state test file.
    from agent.runtime_session_store import RuntimeSessionStore
    from hermes_state import SessionDB
    from hermes_state_runtime import begin_runtime_epoch, mutate_worker_execution, register_worker_execution

    db = SessionDB(tmp_path / 'state.db')
    db.create_session('owned', 'cli', system_prompt='prefix')
    db.create_session('foreign', 'cli', system_prompt='secret')
    epoch = begin_runtime_epoch(db, instance_id='fixture')
    scope = dict(epoch=epoch, execution_id='worker', session_id='owned', generation=0)
    register_worker_execution(db, **scope, kind='compute', adoption_secret='secret')
    store = RuntimeSessionStore(lambda method, **p: mutate_worker_execution(db, **p), scope, tmp_path / 'outbox')
    yield db, store
    store.failure = None
    store.journal['pending'] = []
    store.close()
    db.close()


import sys

import pytest


@pytest.fixture(autouse=True)
def _test_owned_darwin_descriptor_scan(monkeypatch):
    """Real children still hold real temporary DBs; the operator's gateway is excluded.

    psutil's Darwin collector stats every process's open files before filtering
    for the watched DB. That touches real Hermes home and trips the suite's I/O
    guard. All stores and holders in these tests are owned by this test process.
    Keep actual fd inspection and admission logic, without widening that guard.
    """
    if sys.platform != "darwin":
        return
    import hermes_state_holders

    psutil = hermes_state_holders.psutil
    original = psutil.process_iter

    def owned_process_iter(attrs=None, *args, **kwargs):
        if attrs != ["pid", "open_files"]:
            yield from original(attrs, *args, **kwargs)
            return
        for process in psutil.Process().children(recursive=True):
            try:
                process.info = process.as_dict(attrs=attrs)
            except psutil.NoSuchProcess:
                continue
            yield process

    monkeypatch.setattr(psutil, "process_iter", owned_process_iter)
