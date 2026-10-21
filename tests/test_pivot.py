"""Specialists get a pivot surface (primary targets + other discovered endpoints)."""
from owlforge.engine.orchestrator import _surface_with_pivots


def test_pivot_surface_lists_other_endpoints():
    targets = [{"method": "GET", "url": "https://t/catalog", "param": "category"}]
    inv = [
        {"method": "GET", "url": "https://t/catalog", "params": ["category"]},   # == primary
        {"method": "POST", "url": "https://t/catalog/product/stock", "params": ["storeId"]},
        {"method": "POST", "url": "https://t/catalog/cart", "params": ["productId"]},
    ]
    out = _surface_with_pivots(targets, inv)
    assert "Other discovered endpoints" in out
    assert "/catalog/product/stock" in out and "storeId" in out
    assert "/catalog/cart" in out
    # the primary target is still present
    assert "param=category" in out


def test_no_pivots_returns_primary_only():
    targets = [{"method": "GET", "url": "https://t/x", "param": "q"}]
    out = _surface_with_pivots(targets, [{"method": "GET", "url": "https://t/x", "params": ["q"]}])
    assert "Other discovered endpoints" not in out and "https://t/x" in out
