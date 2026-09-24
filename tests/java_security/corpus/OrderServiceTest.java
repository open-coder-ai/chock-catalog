package com.acme.orders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class OrderServiceTest {
    private final OrderService service = new OrderService(new InMemoryOrderRepository(), new FlatRateShipping());

    @Test
    void addsFreeShippingAboveThreshold() {
        BigDecimal subtotal = new BigDecimal("75.00");

        boolean eligible = service.isEligibleForFreeShipping(subtotal);

        assertTrue(eligible);
    }

    @Test
    void chargesShippingBelowThreshold() {
        BigDecimal subtotal = new BigDecimal("10.00");

        boolean eligible = service.isEligibleForFreeShipping(subtotal);

        assertFalse(eligible);
    }

    @Test
    void placesAnOrderForEachLineItem() {
        Customer customer = new Customer("cust-1");
        List<LineItem> items = List.of(new LineItem("sku-1", 2, new BigDecimal("12.50")));

        Order order = service.place(customer, items);

        assertEquals(new BigDecimal("25.00"), order.subtotal());
    }

    @Test
    @Disabled("waiting on ShippingCalculator's new rate table, see ORD-482")
    void appliesRegionalShippingRates() {
        assertTrue(false);
    }
}
