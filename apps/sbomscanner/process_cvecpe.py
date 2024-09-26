import json
import sys

def process_input(input_stream):
    obj = json.load(input_stream)
    for o in obj["CVE_Items"]:
        cve = o["cve"]["CVE_data_meta"]["ID"]
        description = o["cve"]["description"]["description_data"][0]["value"].replace("\r", "").replace("\n", "")
        if "baseMetricV3" in o["impact"]:
            baseSeverity23 = o["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
            baseScore23 = o["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            vectorString3 = o["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
        else:
            if "baseMetricV2" in o["impact"]:
                baseSeverity23 = o["impact"]["baseMetricV2"]["severity"]
                baseScore23 = o["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                vectorString3 = o["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
                baseScore23 = (baseScore23 * 30 / 100) + baseScore23
                baseScore23 = round(baseScore23, 1)
                vectorString3 = "na"
                if baseScore23 > 0 and baseScore23 <= 3.9:
                    baseSeverity23 = "LOW"
                if baseScore23 >= 4 and baseScore23 <= 6.9:
                    baseSeverity23 = "MEDIUM"
                if baseScore23 >= 7 and baseScore23 <= 8:
                    baseSeverity23 = "HIGH"
                if baseScore23 >= 9 and baseScore23 <= 10:
                    baseSeverity23 = "CRITICAL"
                if baseScore23 > 10:
                    baseSeverity23 = "CRITICAL"
                    baseScore23 = 10
            else:
                baseSeverity23 = "na"
                baseScore23 = "na"
                vectorString3 = "na"
        sys.stdout.write("|".join((cve, description, str(baseScore23), baseSeverity23, vectorString3)).strip() + "|")
        for i in o["configurations"]["nodes"]:
            for l in i["children"]:
                for r in l["cpe_match"]:
                    sys.stdout.write(r["cpe23Uri"].strip() + ",")
            for n in i["cpe_match"]:
                sys.stdout.write(n["cpe23Uri"].strip() + ",")
        sys.stdout.write("\n")

if __name__ == "__main__":
    process_input(sys.stdin)