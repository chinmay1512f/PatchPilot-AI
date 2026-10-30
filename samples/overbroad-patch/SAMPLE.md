title: Over-broad AI patch — unnecessary change detection
analysis_type: patch_review
description: An AI coding tool fixed a one-character bug but also rewrote unrelated functions, added a dependency and duplicated validation logic.
bug_description: |
  Items whose quantity is exactly equal to their reorder level are not flagged for restocking.
  restock_needed() should return True when quantity <= reorder_level.
