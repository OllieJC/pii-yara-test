import sys
import os

sys.path.insert(1, os.getcwd())
from yara_handler import YaraHandler


rules_path = os.path.join(os.getcwd(), "rules")


def ft(f):
    fixture_path = os.path.join(os.getcwd(), "tests/fixtures")
    print(fixture_path)
    return f"{fixture_path}/{f}.txt"


def test_pii_name():
    yh = YaraHandler(rules_path)
    tnm = yh.scan_filename(ft("text_no_pii"))
    assert str(tnm) == "[]"

    cnm = yh.scan_filename(ft("code_no_pii"))
    assert str(cnm) == "[]"

    sm = yh.scan_filename(ft("pii_name_match"))
    assert str(sm) == "[Possible_Bulk_Names]"


def test_pii_email():
    yh = YaraHandler(rules_path)
    tnm = yh.scan_filename(ft("text_no_pii"))
    assert str(tnm) == "[]"

    cnm = yh.scan_filename(ft("code_no_pii"))
    assert str(cnm) == "[]"

    sm = yh.scan_filename(ft("pii_email_match"))
    assert str(sm) == "[Possible_Bulk_Emails]"

    ns = yh.scan_filename(ft("pii_email_single"))
    assert str(ns) == "[]"


if __name__ == "__main__":
    test_pii_name()
    test_pii_email()
