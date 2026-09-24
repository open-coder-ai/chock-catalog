package com.acme.shop.order;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.Test;

class OrderServiceTest {

    private final OrderRepository repository = mock(OrderRepository.class);
    private final OrderService service = new OrderService(repository);

    @Test
    void returnsOrdersWithTheRequestedStatus() {
        Order open = new Order(1L, "ada", "OPEN", new BigDecimal("12.50"), LocalDate.of(2026, 9, 1));
        when(repository.findByStatus("OPEN")).thenReturn(List.of(open));

        assertThat(service.withStatus("OPEN")).containsExactly(open);
    }
}
