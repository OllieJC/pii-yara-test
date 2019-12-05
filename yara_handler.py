import yara
import os
import glob


class YaraHandler:
    rules = []

    def __init__(self, rp=False):
        rules_path = "./rules"
        if rp:
            rules_path = rp

        rules_array = {}
        rule_filenames = glob.glob(f"{rules_path}/*.rules")
        for i, f in enumerate(rule_filenames, start=1):
            rules_array[f"ns{i}"] = f

        # print("Loaded:", rules_array)
        self.rules = yara.compile(filepaths=rules_array)

    def scan_filename(self, filename) -> list:
        res = []
        if os.path.isfile(filename):
            res = self.rules.match(filename)
        return res
