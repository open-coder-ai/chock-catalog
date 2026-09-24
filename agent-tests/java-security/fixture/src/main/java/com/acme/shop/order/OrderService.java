package com.acme.shop.order;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

@Service
public class OrderService {

    private final OrderRepository orders;

    public OrderService(OrderRepository orders) {
        this.orders = orders;
    }

    public Optional<Order> find(long id) {
        return orders.findById(id);
    }

    public List<Order> withStatus(String status) {
        return orders.findByStatus(status);
    }
}
