# shop

Tiny checkout/pricing library used by the demo storefront.

- `shop.cart.Cart` — cart lines, subtotal, checkout totals
- `shop.pricing` — discounts, shipping and tax rules

Policy: orders of **$50.00 or more** (after discounts) ship free; otherwise shipping is $4.99.
Tax is 8% of the discounted subtotal (shipping is not taxed).

Run tests with `pytest`.
