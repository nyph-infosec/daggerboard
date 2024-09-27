import json
import logging
import os
from datetime import datetime

import requests

hdir = "daggerboard/nvdrepo"
db_nvd = os.path.join("daggerboard", "nvdrepo", "nvdcvecpe.csv")
db_nvd_tmp = os.path.join("daggerboard", "nvdrepo", "nvdcvecpe.csv_tmp")
nvdurl = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
pid_file = "get_nvd_cve_cpe.pid"
proxysrv = ""
today = datetime.now().strftime("%Y-%m-%d")


try:
    response = requests.get(
        nvdurl, proxies={"http": proxysrv, "https": proxysrv}, timeout=10
    )
    cve_records = json.loads(response.text)["totalResults"]
except Exception as e:
    logging.info(e)
    cve_records = 210000


if not os.path.isfile(db_nvd_tmp):
    with open(db_nvd, "r") as f:
        lines = f.readlines()
        if len(lines) < cve_records:
            with open("last_nvd_update", "w") as f:
                f.write("LAST_UPDATE=2002-01-01 00:00:01")

pid_file_date = datetime.fromtimestamp(os.path.getmtime(pid_file)).strftime("%Y-%m-%d")

if pid_file_date != today:
    os.remove(pid_file)

old_files = [
    f
    for f in os.listdir(os.path.join("daggerboard", "nvdrepo"))
    if f.startswith("nvdcvecpe.csv_") and f.endswith(datetime.now().strftime("%Y"))
]
for old_file in old_files:
    os.remove(os.path.join(hdir, "nvdrepo", old_file))
