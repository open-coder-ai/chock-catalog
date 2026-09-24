package com.acme.data;

import java.sql.*;
import org.springframework.jdbc.core.JdbcTemplate;

public class SearchDao {
    private static final String SELECT = "SELECT id, name FROM product";
    private final JdbcTemplate jdbc;
    private final DataSource ds;

    public List<Product> search(String name, Integer minPrice, String sortColumn) {
        StringBuilder sql = new StringBuilder(SELECT).append(" WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (name != null) { sql.append(" AND name LIKE ?"); args.add("%" + name + "%"); }
        if (minPrice != null) { sql.append(" AND price >= ?"); args.add(minPrice); }
        String column = ALLOWED_SORT.getOrDefault(sortColumn, "name");
        sql.append(" ORDER BY ").append(column);
        return jdbc.query(sql.toString(), mapper, args.toArray());
    }

    public Product byId(long id) throws SQLException {
        try (Connection c = ds.getConnection();
             PreparedStatement ps = c.prepareStatement(SELECT + " WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) { return rs.next() ? map(rs) : null; }
        }
    }

    public int count() {
        return jdbc.queryForObject("SELECT count(*) FROM product", Integer.class);
    }

    public List<Product> named(String name) {
        return namedJdbc.query("SELECT * FROM product WHERE name = :name", Map.of("name", name), mapper);
    }
}
