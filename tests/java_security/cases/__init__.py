"""Every pack's cases, gathered: each pack owns its modules, and the tests read them all from here."""

from __future__ import annotations

from java_security.cases import (
    android,
    build,
    crypto,
    jakarta,
    jakarta_flow,
    java,
    java_flow,
    logging,
    persistence,
    spring,
    spring_flow,
    templates,
)

#: Modules holding rule cases (CASES) and flow cases (FLOW_CASES); a module may hold either or both.
_MODULES = (
    java,
    java_flow,
    crypto,
    spring,
    spring_flow,
    jakarta,
    jakarta_flow,
    persistence,
    templates,
    logging,
    build,
    android,
)

CASES = [case for module in _MODULES for case in getattr(module, "CASES", [])]
FLOW_CASES = [case for module in _MODULES for case in getattr(module, "FLOW_CASES", [])]
