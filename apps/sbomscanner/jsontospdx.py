#!/var/www/Daggerboard/venv/bin/python

import json
import logging
import os
import re
import shutil
from datetime import datetime

from django.conf import settings

basedir = os.getcwd()

logger = logging.getLogger(__name__)

# dirs for conversion
wdir = settings.UPLOAD_DIRECTORY
logfile = settings.SBOMPROCESS_LOGPATH
archive = settings.ARCHIVE_PATH
# wwwdata_uid = pwd.getpwnam("www-data").pw_uid
# wwwdata_gid = pwd.getpwnam("www-data").pw_gid
converted = list()


# Writes to a log file
def writelog(msg):
    with open(logfile, "a+") as log_file:
        now = datetime.now()
        # month = "{:02d}".format(now.month)
        # day = "{:02d}".format(now.day)
        log_file.write(str(now) + " " + msg + "\n")


def parse_json(wdir):  # noqa
    for file in os.listdir(wdir):
        logger.info(f"found file {file}")
        in_file_path = os.path.join(wdir, file)
        if os.path.isfile(in_file_path) and file.endswith(".json"):
            logger.info("[+] Confirmed JSON file, starting parsing...")
            with open(in_file_path, "r") as original_json:
                try:
                    to_parse_json = json.load(original_json)
                    pkg_to_add = list()
                    # get documentname tag
                    try:
                        doc_name = to_parse_json["name"]
                        # create converted fname
                        if len(doc_name) > 0:
                            doc_name = re.sub("\\.", "_", doc_name)
                            doc_name = re.sub(":", "_", doc_name)
                            spdx_name = "".join(re.split("[^a-zA-Z0-9_]*", doc_name))
                            spdx_fn = spdx_name + "_converted.spdx"
                        else:
                            doc_name = re.sub("\\.", "_", file)
                            doc_name = re.sub(":", "_", doc_name)
                            spdx_name = "".join(re.split("[^a-zA-Z0-9_]*", doc_name))
                            spdx_fn = spdx_name + "_converted.spdx"
                    except KeyError:
                        doc_name = re.sub("\\.", "_", file)
                        doc_name = re.sub(":", "_", doc_name)
                        spdx_name = "".join(re.split("[^a-zA-Z0-9_]*", doc_name))
                        spdx_fn = spdx_name + "_converted.spdx"
                    # get spdxVERSION tag
                    try:
                        spdx_version = to_parse_json["spdxVersion"]
                    except KeyError:
                        spdx_version = "SPDX-2.2"
                    # get SPDXID tag
                    try:
                        spdx_id = to_parse_json["SPDXID"]
                    except KeyError:
                        spdx_id = "SPDXRef-DOCUMENT"
                    # get creatororganization tag
                    try:
                        org_parse = to_parse_json["creationInfo"]["creators"]
                        logger.info(f"Org parse val: {org_parse}")
                        org = org_parse[0].split(":")[1]
                    except KeyError:
                        org = ""
                    # parse packages
                    for package in to_parse_json["packages"]:
                        pkg_to_add.append(
                            {
                                "pkg_name": package["name"],
                                "pkg_vers": package["versionInfo"],
                                "pkg_comment": package["sourceInfo"],
                            }
                        )
                    converted_spdx_fn = wdir + spdx_fn
                    logger.info(converted_spdx_fn)
                    with open(converted_spdx_fn, "w") as new_spdx_f:
                        new_spdx_f.write("SPFXVersion: " + spdx_version + "\n")
                        new_spdx_f.write("SPDXID: " + spdx_id + "\n")
                        new_spdx_f.write("DocumentName: " + doc_name + "\n")
                        new_spdx_f.write("Creator: Organization: " + org + "\n")
                        new_spdx_f.write('CreatorComment: "" \n')
                        for pkg_val in pkg_to_add:
                            new_spdx_f.write(
                                "\n"
                                + "PackageName: "
                                + pkg_val["pkg_name"]
                                + "\nPackageVersion: "
                                + pkg_val["pkg_vers"]
                                + "\nPackageComment: "
                                + pkg_val["pkg_comment"]
                                + "\n"
                            )
                        new_spdx_f.close()
                        # os.chown(converted_spdx_fn, wwwdata_uid, wwwdata_gid)
                        # move old file to archive
                        original_json.close()
                        shutil.move(in_file_path, archive + file)
                        # set as converted in log
                        converted.append({"old_f": file, "new_f": converted_spdx_fn})
                        writelog(
                            f"CONVERTED from JSON to SPDX_tag_value: {file} {converted_spdx_fn}"
                        )
                except Exception as e:
                    writelog(
                        "ERR: .JSON"
                        + file
                        + "file not in JSON format, skipping. Error:"
                        + e
                    )


if len(converted) > 0:
    logger.info(
        f"Converted from JSON to SPDX_tag_value: {converted[0]['old_f']} {converted[0]['new_f']}"
    )
