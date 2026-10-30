from decimal import Decimal

import pytest

from shop import Cart


def test_small_order_pays_shipping():
    cart = Cart()
    cart.add("TSHIRT", "Logo T-shirt", "25.00")
    totals = cart.checkout_totals()
    assert totals["shipping"] == Decimal("4.99")
    assert totals["tax"] == Decimal("2.00")
    assert totals["total"] == Decimal("31.99")


def test_large_order_ships_free():
    cart = Cart()
    cart.add("HOODIE", "Hoodie", "60.00")
    assert cart.checkout_totals()["shipping"] == Decimal("0.00")


def test_adding_same_sku_merges_lines():
    cart = Cart()
    cart.add("MUG", "Mug", "8.00")
    cart.add("MUG", "Mug", "8.00", quantity=2)
    assert len(cart.lines) == 1
    assert cart.subtotal == Decimal("24.00")


def test_discount_code_applied():
    cart = Cart(discount_code="save10")
    cart.add("HOODIE", "Hoodie", "100.00")
    totals = cart.checkout_totals()
    assert totals["discounted_subtotal"] == Decimal("90.00")
    assert totals["shipping"] == Decimal("0.00")


def test_unknown_discount_code_rejected():
    cart = Cart(discount_code="FREE100")
    cart.add("MUG", "Mug", "8.00")
    with pytest.raises(ValueError):
        cart.checkout_totals()


def test_empty_cart_has_no_shipping():
    assert Cart().checkout_totals()["total"] == Decimal("0.00")
