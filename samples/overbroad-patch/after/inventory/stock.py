"""Inventory stock helpers."""

import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)


@dataclass
class Item:
    sku: str
    name: str
    quantity: int
    reorder_level: int
    unit_cost: float


class InventoryValidator:
    """Validates inventory items before processing."""

    def __init__(self, strict: bool = True):
        self.strict = strict

    def validate(self, item: Item) -> bool:
        if not item.sku:
            raise ValueError("sku is required")
        if item.quantity < 0:
            raise ValueError("quantity cannot be negative")
        if item.reorder_level < 0:
            raise ValueError("reorder level cannot be negative")
        if item.unit_cost < 0:
            raise ValueError("unit cost cannot be negative")
        return True


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
    InventoryValidator().validate(item)
    needs_restock = item.quantity <= item.reorder_level
    logger.debug("restock check for %s: %s", item.sku, needs_restock)
    return needs_restock


def total_value(items: list[Item]) -> float:
    return round(sum(i.quantity * i.unit_cost for i in items), 2)


def fetch_supplier_price(sku: str) -> float:
    response = requests.get(f"https://supplier.example.com/api/price/{sku}", timeout=5)
    response.raise_for_status()
    return float(response.json()["price"])


def format_report(items: list[Item]) -> str:
    lines = ["SKU      NAME                 QTY  REORDER"]
    for item in items:
        flag = "*" if restock_needed(item) else " "
        lines.append(f"{item.sku:<8} {item.name:<20} {item.quantity:>4} {item.reorder_level:>7} {flag}")
    return "\n".join(lines)
