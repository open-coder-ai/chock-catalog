"""Extra coverage cases for the spring pack, kept separate from spring.py to avoid merge
conflicts with the parallel work adding new rules to this pack.

Rows are (rule id, path, text, line numbers the rule must report); an empty list is a correct
change the rule must stay silent on.
"""

from __future__ import annotations

ERROR_DETAILS = "spring-error-details-exposed"
CSRF_DISABLED = "spring-csrf-disabled"
PERMIT_ALL = "spring-permit-all-catchall"
SESSION_COOKIE = "spring-insecure-session-cookie"
SESSION_FIXATION = "spring-session-fixation-disabled"

_SECURITY_IMPORT = "import org.springframework.security.config.annotation.web.builders.HttpSecurity\n"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    # spring-error-details-exposed, via config_pairs' .properties reader: a comment, a blank
    # line, a line with neither "=" nor ":", and a line whose key comes out empty must all be
    # skipped before the real key is read.
    (
        ERROR_DETAILS,
        "application.properties",
        "# app config\n\nnot-a-valid-line\n=orphan-value\nserver.error.include-exception=true\n",
        [5],
    ),
    # spring-error-details-exposed, via config_pairs' YAML reader: a comment, a blank line, and
    # a plain line with no colon (a folded scalar's continuation, say) must all be skipped too.
    (
        ERROR_DETAILS,
        "application.yml",
        "# top comment\n\nplain-text-no-colon\nserver:\n  error:\n    include-exception: true\n",
        [6],
    ),
    # spring-csrf-disabled: the Kotlin `csrf { }` block's own closing brace falls outside the
    # 6-line scan window, so the disable() call is only ever found by scanning to the window's
    # own end (never a closing brace inside it).
    (
        CSRF_DISABLED,
        "Sec.kt",
        _SECURITY_IMPORT + "csrf {\n    disable()\n    a()\n    b()\n    c()\n    d()\n}\n",
        [2],
    ),
    # spring-csrf-disabled: a Kotlin `csrf { }` block that closes well within the window, but
    # never calls disable() -- a real, narrower CSRF configuration, not a disable.
    (
        CSRF_DISABLED,
        "Sec.kt",
        _SECURITY_IMPORT + "csrf {\n    requireCsrfProtectionMatcher(matcher)\n}\n",
        [],
    ),
    # spring-permit-all-catchall: web.ignoring() with no requestMatchers/antMatchers/mvcMatchers
    # call at all -- ignoring() alone names nothing to scope, so this is not the wildcard form.
    (
        PERMIT_ALL,
        "Sec.java",
        _SECURITY_IMPORT + "web.ignoring().mvcDispatchTypes(DispatcherType.ASYNC);\n",
        [],
    ),
    # spring-insecure-session-cookie: a ResponseCookie chain longer than the 10-line scan window,
    # every call in it secure, and no .build() inside the window either -- the inner scan must
    # run the window out to its own end rather than stop early on a call that never arrives.
    (
        SESSION_COOKIE,
        "Cookie.java",
        'ResponseCookie cookie = ResponseCookie.from("SESSION", token)\n'
        '    .path("/")\n'
        '    .domain("example.com")\n'
        "    .maxAge(3600)\n"
        '    .sameSite("Strict")\n'
        "    .secure(true)\n"
        "    .httpOnly(true)\n"
        '    .comment("session")\n'
        "    .partitioned(false)\n"
        "    .version(1)\n"
        "    .encode();\n",
        [],
    ),
    # spring-session-fixation-disabled: the Kotlin `sessionFixation { }` block's own closing
    # brace falls outside the 6-line scan window, same shape as the csrf-disabled block above.
    (
        SESSION_FIXATION,
        "Sec.kt",
        _SECURITY_IMPORT + "sessionFixation {\n    none()\n    a()\n    b()\n    c()\n    d()\n}\n",
        [2],
    ),
    # spring-session-fixation-disabled: a Kotlin block that closes within the window but never
    # calls none() -- a real session-fixation strategy, not a disable.
    (
        SESSION_FIXATION,
        "Sec.kt",
        _SECURITY_IMPORT + "sessionFixation {\n    migrateSession()\n}\n",
        [],
    ),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
    (
        "view-name: the same concatenation, but the method is @ResponseBody",
        "User.java",
        (
            "@Controller\n"
            "public class User {\n"
            '  @GetMapping("/user")\n'
            "  @ResponseBody\n"
            "  public String user(@RequestParam String lang) {\n"
            '    return "user/" + lang;\n'
            "  }\n}\n"
        ),
        set(),
        {"spring-view-name-injection"},
    ),
]
