import pytest
import sys
from pathlib import Path

# Add project root to path so 'src.validators' resolves dynamically
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.validators import is_valid_ip, is_valid_domain, is_valid_sha256

def test_is_valid_ip():
    assert is_valid_ip("8.8.8.8") == True
    assert is_valid_ip("192.168.1.1") == False  # Private IP blocked
    assert is_valid_ip("999.999.999.999") == False
    assert is_valid_ip("2001:4860:4860::8888") == True  # Valid IPv6

def test_is_valid_domain():
    assert is_valid_domain("google.com") == True
    assert is_valid_domain("attacker.local") == False  # Internal TLD blocked
    assert is_valid_domain("invalid_domain_name") == False

def test_is_valid_sha256():
    valid_hash = "a" * 64
    assert is_valid_sha256(valid_hash) == True
    assert is_valid_sha256("short_hash") == False
    assert is_valid_sha256(valid_hash + "a") == False
