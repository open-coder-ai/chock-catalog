package com.acme.orders;

import java.math.BigDecimal;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class OrderService {
    private static final Logger log = LoggerFactory.getLogger(OrderService.class);
    private static final BigDecimal FREE_SHIPPING_THRESHOLD = new BigDecimal("50.00");
    private static final long DEFAULT_TIMEOUT_MS = 30_000L;

    private final OrderRepository repository;
    private final ShippingCalculator shipping;

    public OrderService(OrderRepository repository, ShippingCalculator shipping) {
        this.repository = repository;
        this.shipping = shipping;
    }

    public Order place(Customer customer, List<LineItem> items) {
        BigDecimal subtotal = BigDecimal.ZERO;
        for (LineItem item : items) {
            subtotal = subtotal.add(item.total());
        }
        BigDecimal shippingCost = subtotal.compareTo(FREE_SHIPPING_THRESHOLD) >= 0
                ? BigDecimal.ZERO
                : shipping.costFor(customer, items);
        Order order = new Order(customer, items, subtotal.add(shippingCost));
        repository.save(order);
        log.info("order {} placed for customer {}", order.id(), customer.id());
        return order;
    }

    public boolean isEligibleForFreeShipping(BigDecimal subtotal) {
        return subtotal.compareTo(FREE_SHIPPING_THRESHOLD) >= 0;
    }

    public List<Order> recentOrders(Customer customer) {
        return repository.findRecentByCustomer(customer, DEFAULT_TIMEOUT_MS);
    }
}
