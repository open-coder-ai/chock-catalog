"""guard-deletion: every guard family and mitigation family, refusing and silent, plus the evasions probed."""

from __future__ import annotations

import pytest
from policies.guard_deletion_kit import judge, verdict

GUARD, MITIGATION = judge.GUARD_RULE, judge.MITIGATION_RULE

#: (removed line, a line that replaces it where one is allowed, family)
GUARD_LINES = [
    ("    if len(buf) > MAX_BODY:", "bound-compare"),
    ("  if (payload.length >= limit) {", "bound-compare"),
    ("    if 0 < size(items) <= cap:", "bound-compare"),
    ("  if (user == null) {", "null-compare"),
    ("    if token is None:", "null-compare"),
    ("  if (x !== undefined) {", "null-compare"),
    ("  if err != nil {", "null-compare"),
    ("    if not ok: return False", "failure-exit"),
    ("        raise PermissionDenied", "failure-exit"),
    ("    throw new ForbiddenError();", "failure-exit"),
    ("    return nil, err", "failure-exit"),
    ("  if (!ok) return -1;", "failure-exit"),
    ("    abort(403)", "failure-exit"),
    ("    assert user.is_staff", "assertion"),
    ("    static_assert(sizeof(T) == 8);", "assertion"),
    ("@login_required", "auth-annotation"),
    ("@PreAuthorize(\"hasRole('ADMIN')\")", "auth-annotation"),
    ("[Authorize]", "auth-annotation"),
    ("@csrf_protect", "auth-annotation"),
    ("app.use(csrfProtection)", "middleware-registration"),
    ("    'django.middleware.csrf.CsrfViewMiddleware',", "middleware-registration"),
    ("MIDDLEWARE = [", "middleware-registration"),
    ("    router.Use(AuthRequired())", "middleware-registration"),
    ("    r.Use(middleware.RequestID)", "middleware-registration"),
    ("Route::get('/x', $f)->middleware('auth');", "middleware-registration"),
    ("protect_from_forgery with: :exception", "middleware-registration"),
    ("@UseGuards(AuthGuard('jwt'))", "middleware-registration"),
    ("app.add_middleware(AuthMiddleware)", "middleware-registration"),
    ("    name = html.escape(name)", "sanitizer-call"),
    ("    out = DOMPurify.sanitize(raw)", "sanitizer-call"),
    ("    arg = shlex.quote(arg)", "sanitizer-call"),
    ("    clean = sanitize_input(raw)", "sanitizer-call"),
    ("    p = os.path.realpath(p)", "path-check"),
    ("    if not p.startswith(base):", "path-check"),
    ("    r = requests.get(u, verify=True)", "tls-verify-true"),
]


@pytest.mark.parametrize(("line", "family"), GUARD_LINES, ids=[f"{f}:{ln.strip()[:30]}" for ln, f in GUARD_LINES])
def test_a_removed_guard_with_no_replacement_asks(line: str, family: str) -> None:
    assert (GUARD, family) in verdict([line], [])


@pytest.mark.parametrize(("line", "_family"), GUARD_LINES, ids=[f"{f}:{ln.strip()[:30]}" for ln, f in GUARD_LINES])
def test_the_same_line_reindented_is_a_replacement(line: str, _family: str) -> None:
    assert verdict([line], [line.strip()]) == []


def test_a_refactored_check_in_the_same_hunk_is_a_replacement() -> None:
    assert (
        verdict(["    if not user.is_admin: raise PermissionDenied"], ["    if user.role != 'admin': raise Denied"])
        == []
    )
    assert verdict(["    if (len > MAX) throw e;"], ["    if (n is None) return;"]) == []


def test_a_replacement_of_another_group_does_not_cancel_the_removal() -> None:
    assert verdict(["@login_required"], ["    if x is None: return"]) == [(GUARD, "auth-annotation")]
    assert verdict(["    out = html.escape(s)"], ["    assert s"]) == [(GUARD, "sanitizer-call")]


def test_a_comment_is_not_a_replacement_and_not_a_removed_guard() -> None:
    assert verdict(["    if len(b) > 3: raise E"], ["    # if len(b) > 3: raise E"]) == [(GUARD, "bound-compare")]
    assert verdict(["    x = 1  # if len(b) > 3: raise E"], []) == []
    assert (
        verdict(
            [
                "    # if len(b) > 3: raise E",
                "// assert ok",
                "/* html.escape(x) */",
                "* escape(x)",
                "-- ENABLE ROW LEVEL SECURITY",
            ],
            [],
        )
        == []
    )
    assert verdict(["    y = 2"], ["    do()  // if len(b) > 3: raise E", "    do()  # escape(x)"]) == []
    assert verdict(["    if len(b) > 3: raise E"], ["    do()  // if len(b) > 3: raise E"]) == [
        (GUARD, "bound-compare")
    ]


def test_a_hunk_that_only_adds_or_renames_is_silent() -> None:
    assert verdict([], ["    if len(b) > 3: raise E"]) == []
    assert (
        verdict(["def old_name(x):", "    return old_name(x - 1)"], ["def new_name(x):", "    return new_name(x - 1)"])
        == []
    )
    assert verdict(["    x = compute()"], ["    x = compute(1)"]) == []


def test_one_removed_guard_family_reports_once_however_many_lines_carry_it() -> None:
    assert verdict(["    if len(a) > 1: raise E", "    if len(b) > 2: raise E"], []) == [(GUARD, "bound-compare")]
    assert verdict(["@login_required", "app.use(auth)"], []) == [
        (GUARD, "auth-annotation"),
        (GUARD, "middleware-registration"),
    ]
    assert verdict(["@login_required", "    out = html.escape(s)"], []) == [
        (GUARD, "auth-annotation"),
        (GUARD, "sanitizer-call"),
    ]


# (removed, added, family): the mitigation is gone or weakened
BLOCKED = [
    (["CFLAGS += -fstack-protector-strong"], [], "stack-protector"),
    (["CFLAGS += -fstack-protector-strong"], ["CFLAGS += -fno-stack-protector"], "stack-protector"),
    (["CFLAGS += -fstack-protector"], ["CFLAGS += -O2"], "stack-protector"),
    (["CPPFLAGS += -D_FORTIFY_SOURCE=2"], ["CPPFLAGS += -U_FORTIFY_SOURCE"], "fortify-source"),
    (["CPPFLAGS += -D_FORTIFY_SOURCE=2"], ["CPPFLAGS += -D_FORTIFY_SOURCE=0"], "fortify-source"),
    (["CFLAGS += -fPIE"], ["CFLAGS += -fno-pie"], "pie"),
    (["LDFLAGS += -pie"], ["LDFLAGS += -no-pie"], "pie"),
    (["LDFLAGS += -Wl,-z,relro,-z,now"], [], "relro"),
    (["LDFLAGS += -Wl,-z,relro,-z,now"], [], "bind-now"),
    (["LDFLAGS += -z noexecstack"], ["LDFLAGS += -z execstack"], "noexecstack"),
    (["res.setHeader('Strict-Transport-Security', 'max-age=63072000')"], [], "hsts"),
    (["SECURE_HSTS_SECONDS = 31536000"], [], "hsts"),
    (["add_header Content-Security-Policy \"default-src 'self'\";"], [], "csp"),
    (["  X-Frame-Options: DENY"], [], "x-frame-options"),
    (["response.headers['X-Content-Type-Options'] = 'nosniff'"], [], "x-content-type-options"),
    (["res.setHeader('X-Frame-Options', 'DENY')"], ["res.removeHeader('X-Frame-Options')"], "x-frame-options"),
    (["  secure: true,"], ["  secure: false,"], "cookie-secure"),
    (["SESSION_COOKIE_SECURE = True"], [], "cookie-secure"),
    (["c.setSecure(true);"], [], "cookie-secure"),
    (["  httpOnly: true,"], ["  httpOnly: false,"], "cookie-httponly"),
    (["c.setHttpOnly(true);"], [], "cookie-httponly"),
    (["Set-Cookie: sid=1; Secure; HttpOnly; SameSite=Lax"], ["Set-Cookie: sid=1"], "cookie-httponly"),
    (["  sameSite: 'strict',"], ["  sameSite: 'none',"], "cookie-samesite"),
    (["r = requests.get(u, verify=True)"], ["r = requests.get(u, verify=False)"], "tls-verify"),
    (["  rejectUnauthorized: true,"], ["  rejectUnauthorized: false,"], "tls-verify"),
    (["tls.Config{InsecureSkipVerify: false}"], ["tls.Config{InsecureSkipVerify: true}"], "tls-verify"),
    (["curl_setopt($c, CURLOPT_SSL_VERIFYPEER, 1);"], ["curl_setopt($c, CURLOPT_SSL_VERIFYPEER, 0);"], "tls-verify"),
    (["NODE_TLS_REJECT_UNAUTHORIZED=1 node app.js"], ["NODE_TLS_REJECT_UNAUTHORIZED=0 node app.js"], "tls-verify"),
    (["ctx.check_hostname = True"], ["ctx.check_hostname = False"], "tls-verify"),
    (["ALTER TABLE t ENABLE ROW LEVEL SECURITY;"], [], "row-level-security"),
    (["ALTER TABLE t FORCE ROW LEVEL SECURITY;"], ["ALTER TABLE t NO FORCE ROW LEVEL SECURITY;"], "row-level-security"),
    (["CREATE POLICY p ON t USING (owner = current_user);"], [], "row-level-security"),
    ([], ["ALTER TABLE t DISABLE ROW LEVEL SECURITY;"], "row-level-security"),
    ([], ["DROP POLICY p ON t;"], "row-level-security"),
    (["chmod 750 /srv/app"], ["chmod 777 /srv/app"], "file-mode"),
    (["os.chmod(p, 0o600)"], ["os.chmod(p, 0o777)"], "file-mode"),
    (["  defaultMode: 0640"], ["  defaultMode: 0666"], "file-mode"),
    (["chmod 755 run.sh"], ["chmod a+w run.sh"], "file-mode"),
    (["  mode: 0640"], ["  mode: 0666"], "file-mode"),
    (["os.makedirs(p, mode=0o700)"], ["os.makedirs(p, mode=0o777)"], "file-mode"),
]


@pytest.mark.parametrize(
    ("removed", "added", "family"), BLOCKED, ids=[f"{b[2]}:{(b[0] or b[1])[0][:28]}" for b in BLOCKED]
)
def test_a_removed_or_weakened_mitigation_is_refused(removed: list[str], added: list[str], family: str) -> None:
    assert (MITIGATION, family) in verdict(removed, added)


KEPT = [
    (["CFLAGS += -fstack-protector"], ["CFLAGS += -fstack-protector-strong"]),
    (["CFLAGS += -fstack-protector-strong"], ["CFLAGS += -fstack-protector-strong -O2"]),
    (["CPPFLAGS += -D_FORTIFY_SOURCE=1"], ["CPPFLAGS += -D_FORTIFY_SOURCE=2"]),
    (["LDFLAGS += -no-pie"], ["LDFLAGS += -pie"]),
    (["res.setHeader('X-Frame-Options', 'DENY')"], ["res.setHeader('X-Frame-Options', 'SAMEORIGIN')"]),
    (["res.removeHeader('X-Frame-Options')"], []),
    (["  secure: true,"], ["  secure: true, path: '/'"]),
    (["r = requests.get(u, verify=True)"], ["r = requests.get(u, verify=CA_BUNDLE)"]),
    (["DROP POLICY IF EXISTS p ON t;"], ["DROP POLICY IF EXISTS p ON t;", "CREATE POLICY p ON t USING (ok);"]),
    (["ALTER TABLE t ENABLE ROW LEVEL SECURITY;"], ["ALTER TABLE t FORCE ROW LEVEL SECURITY;"]),
    (["chmod 755 a"], ["chmod 750 a"]),
    (["chmod 755 a"], []),
    ([], ["chmod 777 /tmp/x"]),
    ([], ["r = requests.get(u, verify=False)"]),
    ([], ["CFLAGS += -fno-stack-protector"]),
    (["    mode='a'; return 404"], ["    mode='b'; return 403"]),  # a status code beside the word mode
    (["retry mode 100"], ["retry mode 202"]),
    (["umask 077"], ["umask 000"]),  # umask digits mean the reverse of chmod's; not read
]


@pytest.mark.parametrize(("removed", "added"), KEPT, ids=[f"{i}" for i in range(len(KEPT))])
def test_a_mitigation_kept_or_only_added_elsewhere_is_not_this_rules_business(
    removed: list[str], added: list[str]
) -> None:
    assert MITIGATION not in [rule for rule, _ in verdict(removed, added)]


def test_a_mitigation_line_is_not_also_asked_about_as_a_guard() -> None:
    assert verdict(["r = requests.get(u, verify=True)"], ["r = requests.get(u, verify=False)"]) == [
        (MITIGATION, "tls-verify")
    ]
    assert verdict(["r = requests.get(u, verify=True)"], []) == [(GUARD, "tls-verify-true")]


def waiver(*, human: bool, committed: frozenset[str] = frozenset()):
    names = {GUARD: "guard-removal", MITIGATION: "mitigation-removal"}

    def waived(hunk: judge.Hunk, involved: list[str], rule: str) -> bool:
        pool = [*hunk.removed, *hunk.added] if human else [raw for raw in involved if raw in committed]
        return any(f"pragma: allowlist {names[rule]}" in raw for raw in pool)

    return waived


def test_a_waiver_clears_only_its_own_rule() -> None:
    swap = (["r = get(u, verify=True)"], ["r = get(u, verify=False)  # pragma: allowlist mitigation-removal"])
    assert verdict(*swap, waived=waiver(human=True)) == []
    assert verdict(*swap, waived=waiver(human=False)) == [(MITIGATION, "tls-verify")]
    wrong = (["r = get(u, verify=True)"], ["r = get(u, verify=False)  # pragma: allowlist guard-removal"])
    assert verdict(*wrong, waived=waiver(human=True)) == [(MITIGATION, "tls-verify")]
    gone = ["    if len(b) > 3: raise E  # pragma: allowlist guard-removal"]
    assert verdict(gone, [], waived=waiver(human=True)) == []
    assert verdict(gone, [], waived=waiver(human=False)) == [(GUARD, "bound-compare")]
    assert verdict(gone, [], waived=waiver(human=False, committed=frozenset(gone))) == []


def test_a_string_or_docstring_is_not_a_replacement_check() -> None:
    assert verdict(["    if len(b) > 3: raise E"], ["    s = 'if y is None: raise E'"]) == [(GUARD, "bound-compare")]
    assert verdict(["    out = html.escape(s)"], ['    doc = "html.escape(s)"']) == [(GUARD, "sanitizer-call")]


def test_an_import_line_and_a_not_implemented_stub_are_not_guards() -> None:
    assert verdict(["import { ErrorMiddleware } from 'x'", "from a import escape", "#include <x.h>"], []) == []
    assert verdict(["    raise NotImplementedError", "    throw new NotImplementedException();"], []) == []


WEAKENED = [
    (["h['Strict-Transport-Security'] = 'max-age=31536000'"], ["h['Strict-Transport-Security'] = 'max-age=0'"], "hsts"),
    (["setHeader('X-Frame-Options', 'DENY')"], ["setHeader('X-Frame-Options', 'ALLOWALL')"], "x-frame-options"),
    (
        ["Content-Security-Policy: default-src 'self'"],
        ["Content-Security-Policy: default-src * 'unsafe-inline'"],
        "csp",
    ),
    (["LDFLAGS += -Wl,-z,relro,-z,now"], ["LDFLAGS += -Wl,-z,relro"], "bind-now"),
    (["LDFLAGS += -Wl,-z,relro,-z,now"], ["LDFLAGS += -Wl,-z,now"], "relro"),
    (
        ["CFLAGS += -fstack-protector-strong"],
        ["CFLAGS += -fstack-protector-strong -fno-stack-protector"],
        "stack-protector",
    ),
    (["CPPFLAGS += -D_FORTIFY_SOURCE=2"], ["CPPFLAGS += -D_FORTIFY_SOURCE=2 -U_FORTIFY_SOURCE"], "fortify-source"),
    (["LDFLAGS += -pie"], ["LDFLAGS += -pie -no-pie"], "pie"),
    (["LDFLAGS += -z noexecstack"], ["LDFLAGS += -z noexecstack -z execstack"], "noexecstack"),
    (
        ["CREATE POLICY p ON t USING (owner = current_user);"],
        ["CREATE POLICY p ON t USING (true);"],
        "row-level-security",
    ),
]


@pytest.mark.parametrize(("removed", "added", "family"), WEAKENED, ids=[w[2] + str(i) for i, w in enumerate(WEAKENED)])
def test_a_weakened_form_that_keeps_the_old_token_is_still_refused(
    removed: list[str], added: list[str], family: str
) -> None:
    assert (MITIGATION, family) in verdict(removed, added)


def test_an_unrelated_verify_setting_is_not_tls_verification() -> None:
    assert verdict(["verify_email = True"], ["verify_email = False"]) == []


def test_a_removed_line_too_long_to_read_asks_unless_waived() -> None:
    long = "x = 1; " * 200
    assert verdict([long], []) == [(GUARD, "long-line")]
    assert verdict([long + " # pragma: allowlist guard-removal"], [], waived=waiver(human=True)) == []


def test_unrelated_words_and_a_documented_tls_fix_do_not_refuse_correct_code() -> None:
    assert (
        verdict(
            ["h['Content-Security-Policy'] = \"default-src 'self'\""],
            ["h['Content-Security-Policy'] = \"default-src 'self'\"; deliver()"],
        )
        == []
    )
    csp = "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'"
    assert verdict([csp], [csp.replace("'self' 'unsafe", "'self' 'nonce-x' 'unsafe")]) == []
    assert verdict(["r = get(u, verify=True)"], ["r = get(u, verify='/etc/ca.pem')"]) == []
    assert verdict(["r = get(u, verify=True)"], ["r = get(u, verify=CA_BUNDLE)"]) == []
    assert verdict(["import os, html", "from a import b"], []) == []
