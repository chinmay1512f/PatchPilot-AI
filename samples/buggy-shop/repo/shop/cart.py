"""Shopping cart and checkout totals."""

from dataclasses import dataclass, field
from decimal import Decimal

from . import pricing


@dataclass
class CartLine:
    sku: str
    name: str
    unit_price: Decimal
    quantity: int = 1

    @property
    def total(self) -> Decimal:
        return self.unit_price * self.quantity


@dataclass
class Cart:
    lines: list[CartLine] = field(default_factory=list)
    discount_code: str | None = None

    def add(self, sku: str, name: str, unit_price: str | Decimal, quantity: int = 1) -> None:
        if quantity <= 0:
            raise ValueError("quantity must be positive")
        price = Decimal(unit_price)
        for line in self.lines:
            if line.sku == sku:
                line.quantity += quantity
                return
        self.lines.append(CartLine(sku, name, price, quantity))

    def remove(self, sku: str) -> None:
        self.lines = [line for line in self.lines if line.sku != sku]

    @property
    def subtotal(self) -> Decimal:
        return pricing.round_money(sum((line.total for line in self.lines), Decimal("0")))

    def checkout_totals(self) -> dict[str, Decimal]:
        discounted = pricing.apply_discount(self.subtotal, self.discount_code)
        shipping = pricing.shipping_cost(discounted) if self.lines else Decimal("0.00")
        tax = pricing.tax(discounted)
        return {
            "subtotal": self.subtotal,
            "discounted_subtotal": discounted,
            "shipping": shipping,
            "tax": tax,
            "total": pricing.round_money(discounted + shipping + tax),
        }
