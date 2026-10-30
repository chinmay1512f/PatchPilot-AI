"""Inventory stock helpers."""

from dataclasses import dataclass


@dataclass
class Item:
    sku: str
    name: str
    quantity: int
    reorder_level: int
    unit_cost: float


def validate_item(item: Item) -> None:
    if not item.sku:
        raise ValueError("sku is required")
    if item.quantity < 0:
        raise ValueError("quantity cannot be negative")
    if item.reorder_level < 0:
        raise ValueError("reorder level cannot be negative")
    if item.unit_cost < 0:
        raise ValueError("unit cost cannot be negative")


def restock_needed(item: Item) -> bool:
    validate_item(item)
    return item.quantity < item.reorder_level


def total_value(items: list[Item]) -> float:
    total = 0.0
    for item in items:
        total += item.quantity * item.unit_cost
    return round(total, 2)


def format_report(items: list[Item]) -> str:
    lines = ['SKU      NAME                 QTY  REORDER']
    for item in items:
        flag = '*' if restock_needed(item) else ' '
        lines.append('%-8s %-20s %4d %7d %s' % (item.sku, item.name, item.quantity, item.reorder_level, flag))
    return '\n'.join(lines)
