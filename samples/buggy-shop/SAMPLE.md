title: Buggy Shop — free-shipping boundary bug
analysis_type: full_repair
description: Small Python checkout library with a real, reproducible pricing bug and a passing test suite that misses it.
bug_description: |
  Customers whose cart comes to exactly $50.00 are still charged $4.99 shipping at checkout,
  even though our policy (and the banner on the checkout page) says orders of $50 or more ship free.
  Example: 2 x "Logo T-shirt" at $25.00 each, no coupon -> checkout shows shipping $4.99.
  Orders above $50 correctly ship free.
