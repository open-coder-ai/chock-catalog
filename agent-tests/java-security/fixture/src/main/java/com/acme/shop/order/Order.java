package com.acme.shop.order;

import java.math.BigDecimal;
import java.time.LocalDate;

public record Order(long id, String customer, String status, BigDecimal total, LocalDate placedOn) {
}
