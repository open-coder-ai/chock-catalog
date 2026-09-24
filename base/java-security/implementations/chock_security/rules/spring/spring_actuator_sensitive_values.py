"""Naming a sensitive actuator endpoint, or unmasking one's values, publishes exactly the secrets
the wildcard-exposure rule already refuses -- named explicitly instead of with `*`."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.spring._config import config_pairs, is_spring_config_file

_FACTS = facts("spring")["actuator_sensitive"]

RULE_ID = "spring-actuator-sensitive-values"

_SHOW_VALUES_MESSAGE = (
    "`{key}: ALWAYS` unmasks every value this endpoint reports to any caller who can reach it, "
    "including credentials the environment or config properties carry. Use WHEN_AUTHORIZED (the "
    "default for env is NEVER; configprops masks by default too) so only an authenticated, "
    "authorized caller sees the raw values."
)
_ENDPOINT_MESSAGE = (
    "Exposing `{endpoint}` over the web publishes {what}. Serve it only to an authenticated "
    "operator channel, or drop it from this list if this service does not need it exposed."
)
_SHUTDOWN_MESSAGE = (
    "This leaves the shutdown endpoint reachable and able to stop the process -- anyone who can "
    "reach it can take the service down. Leave it disabled (the default), or restrict access to it."
)

_WHAT = {
    "heapdump": "a full heap dump, including whatever credentials or session data the process held in memory",
    "env": "every environment variable and property source, credentials included",
    "threaddump": "every thread's stack, which can leak request data captured mid-flight",
    "jolokia": "a JMX bridge that can read and, on some beans, invoke arbitrary operations",
    "shutdown": "a way to stop the process",
    "logfile": "the application's own log file, which often carries data that should not leave it",
}


def _endpoint_names(value: str) -> list[str]:
    return [name.strip().lower() for name in value.split(",") if name.strip()]


def scan(text: FileText) -> Iterator[Finding]:
    """show-values: ALWAYS, a named sensitive endpoint in the exposure list, or shutdown enabled."""
    if not is_spring_config_file(text.path):
        return
    for entry in config_pairs(text):
        line = text.lines[entry.line_no - 1]
        value = entry.value.strip()
        if entry.key in _FACTS["show_values_keys"] and value.strip('"').lower() == _FACTS["show_values_bad"]:
            yield Finding(RULE_ID, text.path, entry.line_no, line, _SHOW_VALUES_MESSAGE.format(key=entry.key))
        elif entry.key == _FACTS["exposure_include_key"] and value != "*":
            for endpoint in _endpoint_names(value):
                if endpoint in _FACTS["sensitive_endpoints"]:
                    message = _ENDPOINT_MESSAGE.format(endpoint=endpoint, what=_WHAT[endpoint])
                    yield Finding(RULE_ID, text.path, entry.line_no, line, message)
        elif entry.key == _FACTS["shutdown_enabled_key"] and value.lower() == "true":
            yield Finding(RULE_ID, text.path, entry.line_no, line, _SHUTDOWN_MESSAGE)
        elif entry.key == _FACTS["shutdown_access_key"] and value.strip('"').lower() == _FACTS["shutdown_access_bad"]:
            yield Finding(RULE_ID, text.path, entry.line_no, line, _SHUTDOWN_MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Sensitive actuator endpoint or value exposed",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(set): management.endpoint.{env,configprops}.show-values=ALWAYS, "
        "heapdump/env/threaddump/jolokia/shutdown/logfile named in exposure.include, or "
        "shutdown enabled/unrestricted -- keep values masked and these endpoints off the web"
    ),
    refuses="show-values=ALWAYS on env/configprops, a sensitive endpoint named in exposure.include, "
    "and shutdown enabled or access=unrestricted",
    silent_on="the default masked show-values, health/info/metrics in exposure.include, and shutdown left disabled"
    " (the wildcard `*` itself is the other actuator rule's own case)",
)
