#!/var/www/Daggerboard/venv/bin/python

import datetime
import logging
import os
import subprocess
import time

import pytz
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

basedir = os.getcwd()

scanner_basedir = "sbomscanner"
proxystatus = os.path.join(scanner_basedir, "proxystatus")
now = datetime.datetime.now(pytz.timezone("US/Eastern")).strftime("%Y-%m-%d %H:%M:%S")
baseurl = "https://services.nvd.nist.gov/rest/json/cves/2.0"

lupdatef = os.path.join(scanner_basedir, "last_nvd_update")
nvd_max_days = 119
resultsperpage = 1000
sleept = 6

# Check if the script is already running
pid = str(os.getpid())
pidfile = os.path.join(scanner_basedir, "get_nvd_cve_cpe.pid")
if os.path.isfile(pidfile):
    logger.info("Pidfile exists")
    exit()
with open(pidfile, "w") as pf:
    pf.write(pid)


# Write LAST_UPDATE value to a file
def write_last_update(last_upd):
    with open(lupdatef, "w") as lnu:
        lnu.write("LAST_UPDATE=" + str(last_upd) + "\n")


# create last_nvd_update file if not there
if not os.path.isfile(lupdatef):
    write_last_update("1999-01-01 00:00:01")

# Work with the NVD data file
bktimestamp = str(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S"))
dbfile = os.path.join(scanner_basedir, "nvdrepo", "nvdcvecpe.csv")
dbfile_bk = dbfile + "_" + bktimestamp
dbfile_tmp = dbfile + "_tmp"
cp_cmd = "cp -f " + dbfile + " " + dbfile_bk
cp_cmd1 = "cp -f " + dbfile + " " + dbfile_tmp
sort_cmd = "sort -u -o " + dbfile_tmp + " " + dbfile_tmp
mv_cmd = "mv -f " + dbfile_tmp + " " + dbfile
rm_cmd = "rm -f " + dbfile_tmp
own_cmd = "chown www-data: " + dbfile

# Backup data file
subprocess.call(cp_cmd, shell=True)
subprocess.call(cp_cmd1, shell=True)

# Open the temp file to append new data
nvd_data_file = open(dbfile_tmp, "a")


proxy = {"https": settings.PROXY_URL}
header = {"Content-Type": "application/json", "apiKey": settings.NVD_API_KEY}


# Write NVD reachability status (w/ or without proxy)
def write_proxy_status(msg):
    with open(proxystatus, "w") as p:
        p.write(now + ": " + msg + "\n")


# Get LAST_UPDATE value from a file
with open(lupdatef, "r") as lu:
    line = lu.readlines()
    for record in line:
        if "LAST_UPDATE" in record:
            lastupdate = record.split("=")[1].strip().replace("'", "").replace('"', "")


# Getting difference in days from last update until now

t = datetime.datetime.strptime(now, "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(
    lastupdate, "%Y-%m-%d %H:%M:%S"
)

days_old = t.days
# print("DAYS OLD: " + str(days_old))

# Create timestamp borders using nvd_max_days between pubStartDate and pubEndDate date until utcnow()

# Define list date_list
date_list = list()


def query_nvd():  # noqa
    # If NVD reachable, get total number of results for a query
    # check for days_old to change the api query

    # if apistr != "":
    #     # get_count= baseurl + '?resultsPerPage=1&pubStartDate={}&pubEndDate={}'.format(startd,endd)
    #     get_count = (
    #         baseurl
    #         + "?resultsPerPage=1&lastModStartDate={}&lastModEndDate={}".format(
    #             startd, endd
    #         )
    #     )
    # else:
    #     exit()

    # print("URL get_count: " + get_count)
    # print("---------------")

    try:
        get_count = (
            baseurl
            + "?resultsPerPage=1&lastModStartDate={}&lastModEndDate={}".format(
                startd, endd
            )
        )
        response = requests.get(
            get_count, headers=header, verify=True, proxies=proxy, timeout=10
        )
        r = response.status_code
        msg = "NVD_REACHABLE"
        write_proxy_status(msg)
        t = response.json()
    except Exception as e:
        msg = f"NVD_NOT_REACHABLE {e}"
        write_proxy_status(msg)
        os.unlink(pidfile)
        exit()

    maxcount = t["totalResults"]
    logger.info("Maxcount Result: " + str(maxcount))

    for stindex in range(0, maxcount, resultsperpage):
        time.sleep(sleept)
        # get_info = baseurl + '?startIndex={}&resultsPerPage={}&pubStartDate={}&pubEndDate={}'.format(stindex,resultsperpage,startd,endd)
        get_info = (
            baseurl
            + "?startIndex={}&resultsPerPage={}&lastModStartDate={}&lastModEndDate={}".format(
                stindex, resultsperpage, startd, endd
            )
        )

        logger.info("URL get_info: " + get_info)
        logger.info("================")

        try:
            response = requests.get(
                get_info, headers=header, verify=True, proxies=proxy, timeout=10
            )
            r = response.status_code
            # sg = "NVD_REACHABLE"
            write_proxy_status(msg)
            t = response.json()
        except Exception as e:
            msg = "NVD_NOT_REACHABLE " + str(e) + " " + str(r)
            write_proxy_status(msg)
            os.unlink(pidfile)
            exit()

        for o in t["vulnerabilities"]:
            cve = o["cve"]["id"]
            description = (
                o["cve"]["descriptions"][0]["value"].replace("\r", "").replace("\n", "")
            )
            if "** REJECT **" in description:
                continue
            if "configurations" not in o["cve"]:
                continue
            if "cvssMetricV31" in o["cve"]["metrics"]:
                baseScore31 = o["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
                    "baseScore"
                ]
                baseSeverity31 = o["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
                    "baseSeverity"
                ]
                vectorString3 = o["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
                    "vectorString"
                ]
                # print(cve,description,baseScore31,baseSeverity31,vectorString3)
            else:
                if "cvssMetricV2" in o["cve"]["metrics"]:
                    baseScore31 = o["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"][
                        "baseScore"
                    ]
                    baseSeverity31 = o["cve"]["metrics"]["cvssMetricV2"][0][
                        "baseSeverity"
                    ]
                    vectorString3 = o["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"][
                        "vectorString"
                    ]
                    baseScore31 = (baseScore31 * 30 / 100) + baseScore31
                    baseScore31 = round(baseScore31, 1)
                    vectorString3 = "na"
                    if baseScore31 > 0 and baseScore31 <= 3.9:
                        baseSeverity31 = "LOW"
                    if baseScore31 >= 4 and baseScore31 <= 6.9:
                        baseSeverity31 = "MEDIUM"
                    if baseScore31 >= 7 and baseScore31 <= 8:
                        baseSeverity31 = "HIGH"
                    if baseScore31 >= 9 and baseScore31 <= 10:
                        baseSeverity31 = "CRITICAL"
                    if baseScore31 > 10:
                        baseSeverity31 = "CRITICAL"
                        baseScore31 = 10
                    # print(cve,description,baseScore31,baseSeverity31,vectorString3)
                else:
                    baseScore31 = "na"
                    baseSeverity31 = "na"
                    vectorString3 = "na"
                    # print(cve,description,baseScore31,baseSeverity31,vectorString3)
            # sys.stdout.write( '|'.join((cve, description,str(baseScore31),baseSeverity31,vectorString3)).strip() + '|')
            nvd_data_file.write(
                "|".join(
                    (cve, description, str(baseScore31), baseSeverity31, vectorString3)
                ).strip()
                + "|"
            )
            # chil = ""
            for i in o["cve"]["configurations"][0]["nodes"]:
                logger.info(f"\tFound cpe match for {cve}...{i['cpeMatch']}")
                # Get all CPE strings if NVD API includes a range of CPEs (versionEndIncluding parameter)
                if (
                    "versionEndIncluding" in i["cpeMatch"][0]
                    or "versionEndExcluding" in i["cpeMatch"][0]
                ):
                    logger.info(f"[+] found version range for {cve}")
                    cpe_range_url = (
                        "https://services.nvd.nist.gov/rest/json/cpematch/2.0?cveId="
                        + cve
                    )
                    try:
                        get_cperesponse = requests.get(
                            cpe_range_url,
                            headers=header,
                            verify=True,
                            proxies=proxy,
                            timeout=10,
                        )
                        cpedata = get_cperesponse.json()
                        for match in cpedata["matchStrings"]:
                            for cpe in match["matchString"]["matches"]:
                                logger.info(
                                    f"found extended cpe match: {cpe} for {cve}"
                                )
                                nvd_data_file.write(cpe["cpeName"].strip() + ",")
                    except Exception as e:
                        for r in i["cpeMatch"]:
                            logger.info(
                                f"Had version key but no matches: {cve}, {r['criteria']}, {e}"
                            )
                            nvd_data_file.write(r["criteria"].strip() + ",")
                else:
                    logger.info("versionmatch not found")
                    for r in i["cpeMatch"]:
                        nvd_data_file.write(r["criteria"].strip() + ",")
            nvd_data_file.write("\n")


if days_old > nvd_max_days:
    # performing floor division
    div = days_old // nvd_max_days

    date_list.append(lastupdate)
    old = datetime.datetime.strptime(
        lastupdate, "%Y-%m-%d %H:%M:%S"
    ) + datetime.timedelta(days=nvd_max_days)
    date_list.append(datetime.datetime.strftime(old, "%Y-%m-%d %H:%M:%S"))

    for _calc in range(div - 1):
        new = old + datetime.timedelta(days=nvd_max_days)
        date_list.append(datetime.datetime.strftime(new, "%Y-%m-%d %H:%M:%S"))
        old = new

    # Insert current time at the end
    date_list.append(now)

    # Process date_list timestamps
    for record in range(len(date_list) - 1):
        write_last_update(date_list[record])
        startd = date_list[record].split(" ")
        startd = startd[0] + "T" + startd[1] + ".000"
        record += 1
        endd = date_list[record].split(" ")
        endd = endd[0] + "T" + endd[1] + ".000"
        logger.info(f"[+] querying dates: {startd}, {endd}")
        query_nvd()
else:
    last_date = datetime.datetime.strptime(lastupdate, "%Y-%m-%d %H:%M:%S")
    last_date = str(last_date).split(" ")
    startd = last_date[0] + "T" + last_date[1] + ".000"
    current_date = str(now).split(" ")
    endd = current_date[0] + "T" + current_date[1] + ".000"
    query_nvd()
    write_last_update(now)

nvd_data_file.close()

subprocess.call(sort_cmd, shell=True)
subprocess.call(mv_cmd, shell=True)
subprocess.call(rm_cmd, shell=True)
subprocess.call(own_cmd, shell=True)

os.unlink(pidfile)
