import sys
import os

sys.path.insert(1, os.getcwd())
from yara_handler import YaraHandler


rules_path = os.path.join(os.getcwd(), "rules")


def test_load_yh():
    yh = YaraHandler(rules_path)
    assert yh.rules != []


if __name__ == "__main__":
    test_load_yh()
