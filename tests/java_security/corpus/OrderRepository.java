package com.acme.data;

import org.springframework.jdbc.core.JdbcTemplate;

@Repository
public class OrderRepository {
    private static final String TABLE = "orders";
    private static final String BASE = "SELECT id, total FROM " + TABLE + " WHERE ";
    private final JdbcTemplate jdbc;
    private final EntityManager em;

    public List<Order> byCustomer(long customerId) {
        return jdbc.query(BASE + "customer_id = ?", mapper, customerId);
    }

    public List<Order> byStatus(String status) {
        return em.createQuery("select o from Order o where o.status = :status", Order.class)
                 .setParameter("status", status).getResultList();
    }

    public int archive(long id) {
        return jdbc.update("UPDATE orders SET archived = true WHERE id = ?", id);
    }
}
