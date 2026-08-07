import pytest
import yara
from pathlib import Path

# Using the project's actual YARA rules directory based on other modules
YARA_RULES_DIR = Path(__file__).parent.parent / "data" / "yara_rules"

def get_yara_rules():
    """Retrieve all .yar and .yara files from the rules directory."""
    if not YARA_RULES_DIR.exists():
        return []
    return list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))

@pytest.mark.parametrize("rule_path", get_yara_rules(), ids=lambda p: p.name)
def test_yara_rule_compiles(rule_path: Path):
    """
    The Compilation Test: Calls yara.compile(filepath=rule_path) for each rule.
    This ensures every rule is syntactically valid and compiles without exceptions 
    before deployment.
    """
    try:
        yara.compile(filepath=str(rule_path))
    except Exception as e:
        pytest.fail(f"Failed to compile {rule_path.name}: {e}")
