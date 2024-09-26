import logging
import os
import subprocess
import urllib.parse

from bs4 import BeautifulSoup


class NvdScraper:
    def __init__(self, proxy=""):
        self.proxy = proxy
        self.tmpf = os.path.join("sbomscanner", "nvd.html")

    def scrape_nvd(self, qr):
        if "cpe:" in qr:
            qry_cpe = qr
            pkg_encoded = urllib.parse.quote(qry_cpe)
            cpeurl = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={pkg_encoded}&search_type=all"
            logging.info("cpeurl", cpeurl)
            cmd = 'curl -x "{}" -k "{}" -o {}'.format(self.proxy, cpeurl, self.tmpf)
        else:
            qry_pkg = qr
            pkg_encoded = urllib.parse.quote(qry_pkg)
            cveurl = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={pkg_encoded}&search_type=all"
            logging.info("cveurl", cveurl)
            cmd = 'curl -k "{}" -o {}'.format(cveurl, self.tmpf)

        ret = subprocess.call(
            cmd, stdout=subprocess.DEVNULL, shell=True, stderr=subprocess.STDOUT
        )
        if ret == 0 and os.stat(self.tmpf).st_size != 0:
            outlist = self.process_html()
            open(self.tmpf, "w").close()
            return outlist
        else:
            logging.info("Failed to pull data from NVD")
            return []

    def process_html(self):
        outlist = []
        with open(self.tmpf, "r", encoding="utf8") as f:
            content = f.read()
            soup = BeautifulSoup(content, "lxml")
            tags_cve = soup.find_all(
                "a", {"data-testid": lambda x: x and x.startswith("vuln-detail-link-")}
            )
            tags_summary = soup.find_all(
                "p", {"data-testid": lambda x: x and x.startswith("vuln-summary-")}
            )
            tags_score = soup.find_all(
                "a", {"data-testid": lambda x: x and x.startswith("vuln-cvss3-link-")}
            )

            for cve, cve_sum, cve_score in zip(tags_cve, tags_summary, tags_score):
                outdict = {}
                outdict["cve_out"] = cve.text if cve else "na"
                outdict["cve_sum_out"] = cve_sum.text if cve_sum else "na"
                if cve_score:
                    cve_score_text = cve_score.text.split()
                    outdict["cve_score_out"] = cve_score_text[0]
                    outdict["cve_severity_out"] = (
                        cve_score_text[1] if len(cve_score_text) > 1 else "na"
                    )
            else:
                outdict["cve_score_out"] = "na"
                outdict["cve_severity_out"] = "na"
                outlist.append(outdict)

        return outlist
