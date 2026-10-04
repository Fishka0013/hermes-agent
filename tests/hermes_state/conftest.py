"""Keep live Darwin descriptor scans inside the test-owned process namespace."""
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
