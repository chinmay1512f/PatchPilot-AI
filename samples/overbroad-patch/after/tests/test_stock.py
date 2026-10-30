from inventory.stock import Item, restock_needed, total_value


def test_low_stock_needs_restock():
    assert restock_needed(Item("A1", "Widget", 2, 5, 1.0))


def test_plenty_of_stock():
    assert not restock_needed(Item("A1", "Widget", 20, 5, 1.0))


def test_total_value():
    items = [Item("A1", "Widget", 2, 5, 1.5), Item("B2", "Gadget", 1, 1, 10.0)]
    assert total_value(items) == 13.0
