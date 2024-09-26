# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

import logging
import os
import re
from datetime import datetime, timedelta
from time import sleep

import pytz
from celery import current_task, shared_task
from django.conf import settings
from rq import get_current_job

from apps.daggerboard_ui.packages.send_smtp_mail import email_user

from .models import Sbom, SbomUpload

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# timestamp
now_time = datetime.now() - timedelta(hours=2)
utc = pytz.UTC

# setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    filename=settings.CELERY_LOGPATH,
    filemode="a",
    format="%(levelname)s - %(asctime)s - %(message)s",
    level=logging.INFO,
)


@shared_task()
def search_log_file(sbom_hash):
    logger.info(f"Checking logfile for {sbom_hash=}")
    lf = settings.CELERY_LOGPATH
    progress_str = re.compile(r"(?:INFO|ERR)-\d-" + sbom_hash)
    with open(lf, "r") as logfile:
        recent_lines = logfile.readlines()[-5:]
        log_matches = [
            re.findall(progress_str, s)[0]
            for s in recent_lines
            if re.search(progress_str, s)
        ]
        if len(log_matches) > 0:
            last_log = log_matches[-1]
        else:
            last_log = ""
        logfile.close()
        if last_log == "INFO-1-" + sbom_hash:
            return {"sbomprocess_complete": True, "result": 1, "err": ""}
        elif last_log == "ERR-2-" + sbom_hash:
            current_task.update_state(
                state="FAILURE",
                meta={
                    "err": "File has already been processed.",
                    "sbomprocess_complete": True,
                },
            )
            return {
                "sbomprocess_complete": True,
                "result": 2,
                "err": "File has already been processed.",
            }
        elif last_log == "ERR-3-" + sbom_hash:
            return {
                "sbomprocess_complete": True,
                "result": 3,
                "err": "PackageName tag missing.",
            }
        elif last_log == "ERR-4-" + sbom_hash:
            return {
                "sbomprocess_complete": True,
                "result": 4,
                "err": "PackageVersion tag missing.",
            }
        elif last_log == "ERR-5-" + sbom_hash:
            return {
                "sbomprocess_complete": True,
                "result": 5,
                "err": "Invalid XML structure.",
            }
        elif last_log == "ERR-6-" + sbom_hash:
            return {
                "sbomprocess_complete": True,
                "result": 6,
                "err": "Invalid file format.",
            }
        elif last_log == "INFO-00-" + sbom_hash:
            return {
                "sbomprocess_complete": False,
                "result": 0,
                "err": "Processing in progress.",
            }
        else:
            return {"sbomprocess_complete": False, "result": 0, "err": ""}


@shared_task(name="check_log_file")
def check_log_file(sbom_hash, fname):
    logger.info(f"Processing {sbom_hash=}, {fname=}")
    job = get_current_job()
    sbom_hash_q = (
        Sbom.objects.filter(filehash=sbom_hash)
        .values("filehash", "documentname", "id", "uploadtime")
        .last()
    )
    sbom_upload_q = SbomUpload.objects.filter(sha1=sbom_hash).last()
    job_complete = False

    # job timeout seconds = 3 minutes
    secs = 180
    while not job_complete:
        for sec in range(secs):
            # check if file was already processed successfully, else follow log
            logger.info("Checking if SHA1 present in DB...")
            try:
                db_query_len = len(sbom_hash_q)
            except TypeError:
                db_query_len = 0
            if db_query_len > 0:
                logger.info("[+] SHA1 present in DB...adding link in our DB")
                if sbom_hash_q["uploadtime"].replace(tzinfo=utc) < now_time.replace(
                    tzinfo=utc
                ):
                    job.meta["err"] = "Duplicate SBOM uploaded."
                    job.save_meta()
                job.meta["check_type"] = "db_query"
                job.meta["progress"] = 100
                job.meta["status_code"] = 1
                # link upload to SBOM entry in DB
                sbom_upload_q.sbomid_sbomupload_id = sbom_hash_q["id"]
                sbom_upload_q.save()
                job.save_meta()
                job_complete = True
                break
            else:
                # hash not present in db, need to check log file for upload status
                logger.info("checking hash status in logfile...")
                log_results = search_log_file(sbom_hash)
                logger.info(f"logfile results =  {log_results=}")
                if log_results["sbomprocess_complete"]:
                    logger.info(f"log results: {log_results}")
                    job.meta["progress"] = 100
                    job.meta["check_type"] = "log_query"
                    job.meta["status_code"] = log_results["result"]
                    job.meta["err"] = log_results["err"]
                    job.save_meta()
                    job_complete = True
                    break
            progress = int(sec / secs * 100)
            job.meta["progress"] = progress
            job.meta["check_type"] = "timer"
            job.meta["status_code"] = 0
            job.save_meta()
            sleep(1)


@shared_task(name="email_task")
def email_task(users_email, filename):
    email_subject = "Your SBOM analysis is ready!"
    sbom_proces_completed_status = True
    if sbom_proces_completed_status:
        body_text_1 = (
            f"This is a notification that <b>{filename}</b> has completed processing."
        )
        body_text_2 = "Please login to daggerboard to view resulsts"
        body_text_3 = "Thank you for using DaggerBoard!"
    else:
        email_subject = "Your SBOM analysis failed!"
        body_text_1 = (
            f"This is a notification that <b>{filename}</b> has failed processing."
        )
        body_text_2 = "Please check the SBOM and try again."
        body_text_3 = "Thank you for using DaggerBoard!"
    if settings.EMAIL_HOST:
        logger.info("Sending email notification to user...")
        email_user.send_email(
            subject=email_subject,
            sender=settings.DEFAULT_FROM_EMAIL,
            text="Notification from Daggerboard",
            host=settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            receivers=[users_email],
            html=f"""
                        <!DOCTYPE html>
                        <html>
                            <body>
                                <div style="background-color:#D3D3D3;padding:5px;">
                                    <h1 style="text-align:center; font-family: 'Source Sans Pro', sans-serif; font-size: 2.5rem">
                                        <span style="color: #FFFFFF;">Daggerboard</span>
                                    </h1>
                                </div>
                                <div style="text-align:center;padding:10px 10px;">
                                    <br>
                                    <h4>{body_text_1}</h4>
                                    <h4>{body_text_2}</h4>
                                    <h4>{body_text_3}</h4>
                                    <br>
                                </div>
                            </body>
                            </html>
                        """,
        )
