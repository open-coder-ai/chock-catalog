"""Every pack's cases, gathered: the check reads these, and each pack owns its own module."""

from __future__ import annotations

from java_security_cases import android, build, crypto, jakarta, java, logging, persistence, spring, templates

_MODULES = (java, crypto, spring, jakarta, persistence, templates, logging, build, android)

CASES = [case for module in _MODULES for case in module.CASES]
FLOW_CASES = [case for module in _MODULES for case in module.FLOW_CASES]
