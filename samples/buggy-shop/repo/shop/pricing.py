"""Pricing rules: discounts, shipping and tax."""

from decimal import ROUND_HALF_UP, Decimal

FREE_SHIPPING_THRESHOLD = Decimal("50.00")
STANDARD_SHIPPING = Decimal("4.99")
TAX_RATE = Decimal("0.08")

DISCOUNT_CODES = {
    "SAVE10": Decimal("10"),
    "SAVE25": Decimal("25"),
    "STAFF50": Decimal("50"),
}


def round_money(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def discount_percent(code: str | None) -> Decimal:
    if not code:
        return Decimal("0")
    try:
        return DISCOUNT_CODES[code.strip().upper()]
    except KeyError:
        raise ValueError(f"unknown discount code: {code}") from None


def apply_discount(subtotal: Decimal, code: str | None) -> Decimal:
    """Return the subtotal after applying a percentage discount code."""
    percent = discount_percent(code)
    return round_money(subtotal * (Decimal("100") - percent) / Decimal("100"))


def shipping_cost(discounted_subtotal: Decimal) -> Decimal:
    """Orders of $50.00 or more (after discounts) ship free."""
    if discounted_subtotal > FREE_SHIPPING_THRESHOLD:
        return Decimal("0.00")
    return STANDARD_SHIPPING


def tax(discounted_subtotal: Decimal) -> Decimal:
    return round_money(discounted_subtotal * TAX_RATE)
