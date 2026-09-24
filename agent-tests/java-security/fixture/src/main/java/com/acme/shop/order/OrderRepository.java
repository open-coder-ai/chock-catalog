package com.acme.shop.order;

import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class OrderRepository {

    private static final RowMapper<Order> ROWS = (rs, n) -> new Order(
            rs.getLong("id"),
            rs.getString("customer"),
            rs.getString("status"),
            rs.getBigDecimal("total"),
            rs.getDate("placed_on").toLocalDate());

    private final JdbcTemplate jdbc;

    public OrderRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Order> findById(long id) {
        return jdbc.query("SELECT * FROM orders WHERE id = ?", ROWS, id).stream().findFirst();
    }

    public List<Order> findByStatus(String status) {
        return jdbc.query("SELECT * FROM orders WHERE status = ? ORDER BY placed_on DESC", ROWS, status);
    }
}
