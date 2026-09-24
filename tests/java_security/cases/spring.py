"""Cases for the spring pack: Spring.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

from java_security.cases.spring_edges import CASES as EDGE_CASES

CREDENTIALS = "config.setAllowCredentials(true);\n"

_SECURITY_IMPORT = "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    (
        "java-cors-wildcard-credentials",
        "Cors.java",
        'config.setAllowCredentials(true);\nconfig.setAllowedOrigins(List.of("*"));\n',
        [2],
    ),
    ("java-cors-wildcard-credentials", "Api.java", '@CrossOrigin(origins = "*", allowCredentials = "true")\n', [1]),
    ("java-cors-wildcard-credentials", "Cors.java", 'config.setAllowedOrigins(List.of("*"));\n', []),
    (
        "java-cors-wildcard-credentials",
        "Cors.java",
        'config.setAllowCredentials(true);\nconfig.setAllowedOrigins(List.of("https://app.example.com"));\n',
        [],
    ),
    (
        "java-cors-wildcard-credentials",
        "Cors.java",
        'config.setAllowCredentials(true);\nconfig.setAllowedOriginPatterns(List.of("*"));\n',
        [],
    ),
    (
        "java-cors-wildcard-credentials",
        "Cors.java",
        'config.setAllowCredentials(true);\nconfig.addAllowedOriginPattern("*");\n',
        [],
    ),
    ("java-actuator-wildcard-exposure", "application.properties", "management.endpoints.web.exposure.include=*\n", [1]),
    (
        "java-actuator-wildcard-exposure",
        "application.yml",
        'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n',
        [5],
    ),
    (
        "java-actuator-wildcard-exposure",
        "application.properties",
        "management.endpoints.web.exposure.include=health,info,metrics\n",
        [],
    ),
    ("java-actuator-wildcard-exposure", "codecov.yml", 'coverage:\n  include: "*"\n', []),
    (
        "java-actuator-wildcard-exposure",
        "codecov.yml",
        '# operational exposure notes: keep actuator endpoints minimal\ncoverage:\n  include: "*.yml"\n',
        [],
    ),
    (
        "java-actuator-wildcard-exposure",
        "application.yml",
        'management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\n  other:\n    include: "*"\n',
        [],
    ),
    ("java-actuator-wildcard-exposure", "application.properties", "server.port=8080\n", []),
    # spring-csrf-disabled
    ("spring-csrf-disabled", "Sec.java", _SECURITY_IMPORT + ".csrf().disable()\n", [2]),
    ("spring-csrf-disabled", "Sec.java", _SECURITY_IMPORT + "http.csrf(AbstractHttpConfigurer::disable);\n", [2]),
    ("spring-csrf-disabled", "Sec.java", _SECURITY_IMPORT + "http.csrf(csrf -> csrf.disable());\n", [2]),
    ("spring-csrf-disabled", "Sec.kt", _SECURITY_IMPORT + "csrf {\n    disable()\n}\n", [2]),
    (
        "spring-csrf-disabled",
        "Sec.java",
        _SECURITY_IMPORT + 'http.csrf(csrf -> csrf.ignoringRequestMatchers("/webhooks/**"));\n',
        [],
    ),
    ("spring-csrf-disabled", "Plain.java", ".csrf().disable()\n", []),
    # spring-permit-all-catchall
    (
        "spring-permit-all-catchall",
        "Sec.java",
        _SECURITY_IMPORT + "http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());\n",
        [2],
    ),
    ("spring-permit-all-catchall", "Sec.java", _SECURITY_IMPORT + 'auth.requestMatchers("/**").permitAll();\n', [2]),
    ("spring-permit-all-catchall", "Sec.java", _SECURITY_IMPORT + 'web.ignoring().requestMatchers("/**");\n', [2]),
    (
        "spring-permit-all-catchall",
        "Sec.java",
        _SECURITY_IMPORT + 'auth.requestMatchers("/public/**").permitAll();\n',
        [],
    ),
    (
        "spring-permit-all-catchall",
        "Sec.java",
        _SECURITY_IMPORT + 'auth.requestMatchers("/actuator/health").permitAll();\n',
        [],
    ),
    ("spring-permit-all-catchall", "Sec.java", _SECURITY_IMPORT + "auth.anyRequest().authenticated();\n", []),
    # spring-weak-password-encoder
    ("spring-weak-password-encoder", "Enc.java", "PasswordEncoder e = new NoOpPasswordEncoder();\n", [1]),
    ("spring-weak-password-encoder", "Enc.java", 'String p = "{noop}password123";\n', [1]),
    ("spring-weak-password-encoder", "Users.java", "UserBuilder u = User.withDefaultPasswordEncoder();\n", [1]),
    (
        "spring-weak-password-encoder",
        "src/test/java/UsersTest.java",
        "UserBuilder u = User.withDefaultPasswordEncoder();\n",
        [],
    ),
    ("spring-weak-password-encoder", "Enc.java", "PasswordEncoder e = new BCryptPasswordEncoder();\n", []),
    (
        "spring-weak-password-encoder",
        "Enc.java",
        "PasswordEncoder e = PasswordEncoderFactories.createDelegatingPasswordEncoder();\n",
        [],
    ),
    ("spring-weak-password-encoder", "Enc.java", 'String p = "{bcrypt}$2a$10$abc";\n', []),
    # spring-plaintext-secret-property
    ("spring-plaintext-secret-property", "application.properties", "spring.datasource.password=hunter2\n", [1]),
    ("spring-plaintext-secret-property", "application.yml", "app:\n  client-secret: abc123\n", [2]),
    ("spring-plaintext-secret-property", "application.properties", "spring.datasource.password=${DB_PASSWORD}\n", []),
    ("spring-plaintext-secret-property", "application.properties", "spring.datasource.password={cipher}AQAbcdef\n", []),
    (
        "spring-plaintext-secret-property",
        "src/test/resources/application.properties",
        "spring.datasource.password=hunter2\n",
        [],
    ),
    ("spring-plaintext-secret-property", "application.properties", "server.port=8080\n", []),
    # spring-h2-console-remote
    ("spring-h2-console-remote", "application.properties", "spring.h2.console.settings.web-allow-others=true\n", [1]),
    ("spring-h2-console-remote", "application.properties", "spring.h2.console.settings.web-allow-others=false\n", []),
    ("spring-h2-console-remote", "application.properties", "server.port=8080\n", []),
    # spring-error-details-exposed
    ("spring-error-details-exposed", "application.properties", "server.error.include-stacktrace=always\n", [1]),
    ("spring-error-details-exposed", "application.properties", "server.error.include-exception=true\n", [1]),
    ("spring-error-details-exposed", "application.properties", "server.error.include-stacktrace=never\n", []),
    ("spring-error-details-exposed", "application.properties", "server.error.include-exception=false\n", []),
    # spring-actuator-sensitive-values
    ("spring-actuator-sensitive-values", "application.properties", "management.endpoint.env.show-values=ALWAYS\n", [1]),
    (
        "spring-actuator-sensitive-values",
        "application.properties",
        "management.endpoints.web.exposure.include=health,heapdump,info\n",
        [1],
    ),
    ("spring-actuator-sensitive-values", "application.properties", "management.endpoint.shutdown.enabled=true\n", [1]),
    (
        "spring-actuator-sensitive-values",
        "application.properties",
        "management.endpoint.env.show-values=WHEN_AUTHORIZED\n",
        [],
    ),
    (
        "spring-actuator-sensitive-values",
        "application.properties",
        "management.endpoints.web.exposure.include=health,info,metrics\n",
        [],
    ),
    ("spring-actuator-sensitive-values", "application.properties", "management.endpoints.web.exposure.include=*\n", []),
    # spring-security-debug
    ("spring-security-debug", "Sec.java", _SECURITY_IMPORT + "@EnableWebSecurity(debug = true)\n", [2]),
    ("spring-security-debug", "Sec.java", _SECURITY_IMPORT + "web.debug(true);\n", [2]),
    ("spring-security-debug", "Sec.java", _SECURITY_IMPORT + "@EnableWebSecurity\n", []),
    ("spring-security-debug", "Sec.java", _SECURITY_IMPORT + "web.debug(false);\n", []),
    # spring-session-fixation-disabled
    ("spring-session-fixation-disabled", "Sec.java", _SECURITY_IMPORT + ".sessionFixation().none()\n", [2]),
    ("spring-session-fixation-disabled", "Sec.java", _SECURITY_IMPORT + "sessionFixation(s -> s.none());\n", [2]),
    ("spring-session-fixation-disabled", "Sec.kt", _SECURITY_IMPORT + "sessionFixation { none() }\n", [2]),
    ("spring-session-fixation-disabled", "Sec.java", _SECURITY_IMPORT + ".sessionFixation().migrateSession()\n", []),
    # spring-security-headers-disabled
    ("spring-security-headers-disabled", "Sec.java", _SECURITY_IMPORT + ".headers().disable()\n", [2]),
    ("spring-security-headers-disabled", "Sec.java", _SECURITY_IMPORT + ".frameOptions().disable()\n", [2]),
    ("spring-security-headers-disabled", "Sec.java", _SECURITY_IMPORT + "headers(h -> h.disable());\n", [2]),
    ("spring-security-headers-disabled", "Sec.java", _SECURITY_IMPORT + ".frameOptions().sameOrigin()\n", []),
    # spring-insecure-session-cookie
    ("spring-insecure-session-cookie", "application.properties", "server.servlet.session.cookie.secure=false\n", [1]),
    (
        "spring-insecure-session-cookie",
        "application.properties",
        "server.servlet.session.cookie.http-only=false\n",
        [1],
    ),
    (
        "spring-insecure-session-cookie",
        "Cookie.java",
        'ResponseCookie cookie = ResponseCookie.from("SESSION", token)\n    .httpOnly(true)\n    .secure(false)\n    .build();\n',
        [3],
    ),
    ("spring-insecure-session-cookie", "application.properties", "server.servlet.session.cookie.secure=true\n", []),
    (
        "spring-insecure-session-cookie",
        "Cookie.java",
        'ResponseCookie cookie = ResponseCookie.from("SESSION", token)\n    .httpOnly(true)\n    .secure(true)\n    .build();\n',
        [],
    ),
    # spring-devtools-remote
    ("spring-devtools-remote", "application.properties", "spring.devtools.remote.secret=change-me\n", [1]),
    (
        "spring-devtools-remote",
        "src/test/resources/application.properties",
        "spring.devtools.remote.secret=change-me\n",
        [],
    ),
    ("spring-devtools-remote", "application.properties", "server.port=8080\n", []),
    (
        "spring-plaintext-secret-property",
        "src/main/resources/application.properties",
        "app.security.token=true\napp.jwt.secret=3600\napp.token=abc123def456\n",
        [3],
    ),
    *EDGE_CASES,
]
