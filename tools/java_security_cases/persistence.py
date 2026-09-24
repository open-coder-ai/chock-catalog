"""Cases for the persistence pack: Persistence.

CASES rows are (rule id, path, text, line numbers the rule must report); an empty list is a
correct change the rule must stay silent on. FLOW_CASES rows are (label, path, text, rule ids
`evaluate` must report over every rule, rule ids this case is evidence about): a case whose
expected set leaves out a rule it is about proves that rule stays silent there.
"""

from __future__ import annotations

MAPPER = '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\n'

#: (rule id, path, text, lines)
CASES: list[tuple[str, str, str, list[int]]] = [
    ('java-sqli-mybatis-interpolation', 'UserMapper.xml',
     '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\nSELECT * FROM t ORDER BY ${col}', [3]),
    ('java-sqli-mybatis-interpolation', 'UserMapper.java',
     'import org.apache.ibatis.annotations.Select;\n@Select("SELECT * FROM ${t}")\n', [2]),
    ('java-sqli-mybatis-interpolation', 'UserMapper.xml',
     '<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN">\n<mapper namespace="a">\nSELECT * FROM t WHERE id = #{id}', []),
    ('java-sqli-mybatis-interpolation', 'pom.xml',
     '<project>\n  <version>${project.version}</version>\n</project>\n', []),
    ('java-sqli-mybatis-interpolation', 'Config.java',
     'import org.springframework.beans.factory.annotation.Value;\n@Value("${app.url}")\n', []),
]

#: (label, path, text, expected rule ids, rule ids this case is about)
FLOW_CASES: list[tuple[str, str, str, set[str], set[str]]] = [
]
