"""One exception identity for imported and --run-module release entrypoints."""


class ReleaseError(RuntimeError):
    pass
