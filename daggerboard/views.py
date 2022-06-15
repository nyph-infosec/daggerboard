import csv
import logging
import re
from datetime import date, datetime, timedelta

import django_rq
import environ
import pandas as pd
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Count, F, Q, Sum
from django.db.models.functions import TruncMonth, TruncYear
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views import View
from grading.models import GradeThresholds, GradeWeights

from .forms import SbomForm, vendorPickerform
from .models import Cve, Package, Sbom, SbomUpload
from .rbac import *
from .tasks import check_log_file

# Read .env file
env = environ.Env()
environ.Env.read_env()

# Logging for system
logger = logging.getLogger(__name__)
# Init logger
logging.basicConfig(
    filename=env("LOGPATH"),
    filemode="a",
    format="%(levelname)s - %(asctime)s - %(message)s",
    level=logging.INFO,
)


class uploadProgressChk(View):
    """
    View for the upload status. Called by upload.status.js on each page.
    Checks the django-rq jobs for upload status.
    Actual job processing is done in tasks.py.
    """
    def get(self, request):
        job_list = dict()
        try:
            cache_job_list = self.request.session["sbom_uploads"]["results"]
        except KeyError:
            cache_job_list = dict()
            self.request.session["sbom_uploads"]["results"] = {}
        process_status = False
        try:
            session_queue = self.request.session["sbom_uploads"]["upload_queue"]
        except KeyError:
            session_queue = list()
        updated_session_queue = [x for x in session_queue]
        if len(session_queue) > 0:
            for job_id in session_queue:
                job = django_rq.get_queue().fetch_job(job_id)
                if job:
                    response = {
                        "status": job.get_status(),
                        "check_type": job.meta.get("check_type", ""),
                        "status_code": job.meta.get("status_code", ""),
                        "filename": job.meta.get("sbom_filename", ""),
                        "error_code": job.meta.get("err", ""),
                    }
                    if (
                        response["check_type"] == "timer"
                        and response["status"] == "failed"
                    ):
                        response["error_code"] = "Upload timed out"
                    if (
                        response["status"] == "queued"
                        or response["status"] == "started"
                        or response["status"] == "failed"
                    ) and response["status_code"] == "":
                        response["status_code"] = 0
                    if (
                        int(response["status_code"]) > 0
                        or response["status"] == "failed"
                        or response["status"] == "finished"
                        or response["status"] == "invalid"
                        or response["status"] == "cancelled"
                        or response["status"] == "stopped"
                    ):
                        job_list[job_id] = response
                        ## update cached jobs in session object
                        cache_job_list[job_id] = response
                        ## remove job from queue in session
                        updated_session_queue.remove(job_id)
                        self.request.session.modified = True
                    elif (
                        int(response["status_code"]) == 0
                        or response["status"] == "queued"
                        or response["status"] == "started"
                        or response["status"] == "scheduled"
                        or response["status"] == "deferred"
                    ):
                        job_list[job_id] = response
                else:
                    response = {"status": "invalid", "status_code": "11"}
                    cache_job_list[job_id] = response
                    try:
                        del job_list[job_id]
                    except KeyError:
                        pass
                    ## remove job from queue in session
                    updated_session_queue.remove(job_id)
                    self.request.session.modified = True
        else:
            process_status = False
        if len(updated_session_queue) > 0:
            process_status = True
        self.request.session["sbom_uploads"]["upload_queue"] = updated_session_queue
        ## cleanup result dict to add max values in dropdown:
        if len(cache_job_list) > 4:
            prev_4_uploads = {
                K: V for (K, V) in [x for x in cache_job_list.items()][-4:]
            }
            self.request.session["sbom_uploads"]["results"] = prev_4_uploads
        else:
            self.request.session["sbom_uploads"]["results"] = cache_job_list
        self.request.session.modified = True
        job_list.update(cache_job_list)
        return JsonResponse({"active_jobs": job_list, "process_status": process_status})


def get_grade_weight_configs(risk_type):
    """
    Function to retrieve custom admin score configs
    """
    try:
        score_configs = GradeWeights.objects.all().values()[0]
        if risk_type == "critical":
            risk_weight = score_configs["crit_weight"]
        elif risk_type == "high":
            risk_weight = score_configs["high_weight"]
        elif risk_type == "medium":
            risk_weight = score_configs["medium_weight"]
        elif risk_type == "low":
            risk_weight = score_configs["low_weight"]
        elif risk_type == "total":
            risk_weight = (
                score_configs["crit_weight"]
                + score_configs["high_weight"]
                + score_configs["medium_weight"]
                + score_configs["low_weight"]
            )
        else:
            logging.info("A risk_type was not provided")
        return risk_weight
    except Exception as e:
        logging.info("Invalid score type requested")


def get_letter_grade_thresholds():
    """
    Function to retrieve letter grade thresholds from admin config.
    """
    try:
        getAdminThresholds = GradeThresholds.objects.values()
        thresholds = [letterGrade for letterGrade in getAdminThresholds][0]
        return thresholds
    except Exception as e:
        logging.info(f"An error occured retreiving grade thresholds:{e}")


def getPrevUploads():
    """
    Queries most recent SBOM uploads.
    """
    recent_upload_q = (
        SbomUpload.objects.filter(sbomid_sbomupload__isnull=False)
        .values("sbomid_sbomupload__documentname", "uploadtime")
        .order_by("uploadtime")[:3]
    )
    return recent_upload_q


def scorecardCSVQueries(type, input_id):
    """
    Helper function for genreport(), which exports a CSV file.
    Queries the database for severities if a Vendor type.
    If SBOM type then queries database for SBOM package information.
    """
    if type == "vendor":
        ven_query = (
            Sbom.objects.filter(vendorname=input_id)
            .prefetch_related("cves_sbom")
            .values("id", "documentname", "vendorname", "uploadtime")
            .annotate(
                cve_crit=(
                    Count("id", filter=(Q(cves_sbom__cvss3_severity="CRITICAL")))
                ),
                cve_high=(Count("id", filter=Q(cves_sbom__cvss3_severity="HIGH"))),
                cve_med=(Count("id", filter=Q(cves_sbom__cvss3_severity="MEDIUM"))),
                cve_low=(Count("id", filter=Q(cves_sbom__cvss3_severity="LOW"))),
                total_cves=(Count("id", filter=~Q(cves_sbom__cve="na"))),
                crit_wt=get_grade_weight_configs("critical") * F("cve_crit"),
                high_wt=F("cve_high") * get_grade_weight_configs("high"),
                med_wt=F("cve_med") * get_grade_weight_configs("medium"),
                wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                sbom_grade=F("wt") / get_grade_weight_configs("total"),
                sum_cvss=(
                    Sum(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
                total_cvss=(
                    Count(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
            )
            .order_by("uploadtime")
        )
        return ven_query
    elif type == "sbom":
        sbom_query = (
            Package.objects.filter(sbomid_packages=input_id)
            .prefetch_related("cves_package", "cpes_package", "sbomid_packages")
            .values(
                "id",
                "packagename",
                "packageversion",
                "cves_package__cve",
                "cves_package__cve_sum",
                "cves_package__cvss3_score",
                "cves_package__cve_exploit",
                "sbomid_packages__documentname",
                "sbomid_packages__vendorname",
            )
            .exclude(cves_package__cve="na")
            .order_by("id")
        )
        return sbom_query


def scorecardOverviewQueries(type, query_id):
    if type == "vendor":
        vendor_overview_query = (
            Sbom.objects.filter(vendorname=query_id)
            .prefetch_related("cves_sbom")
            .values("id", "documentname", "vendorname", "uploadtime")
            .annotate(
                cve_crit=(
                    Count("id", filter=(Q(cves_sbom__cvss3_severity="CRITICAL")))
                ),
                cve_high=(Count("id", filter=Q(cves_sbom__cvss3_severity="HIGH"))),
                cve_med=(Count("id", filter=Q(cves_sbom__cvss3_severity="MEDIUM"))),
                cve_low=(Count("id", filter=Q(cves_sbom__cvss3_severity="LOW"))),
                total_cves=(Count("id", filter=~Q(cves_sbom__cve="na"))),
                total_exploits=(
                    Count("id", filter=~Q(cves_sbom__cve_exploit="exploit_not_found"))
                ),
                crit_wt=40 * F("cve_crit"),
                high_wt=F("cve_high") * 10,
                med_wt=F("cve_med") * 3,
                wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                sbom_grade=F("wt") / get_grade_weight_configs("total"),
                sum_cvss=(
                    Sum(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
                total_cvss=(
                    Count(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
            )
            .order_by("uploadtime")
        )
        ## handle SBOM deletion
        if len(vendor_overview_query) < 1:
            return {"vendor_err": "not_found_in_db"}
        # calculate CVSS average and total CVE counts for vendor
        agg_cvss_score = vendor_overview_query.aggregate(Sum("sum_cvss"))
        agg_total_cves = vendor_overview_query.aggregate(Sum("total_cves"))
        agg_total_cvss_score = vendor_overview_query.aggregate(Sum("total_cvss"))
        vendor_sbom_total = vendor_overview_query.count()
        try:
            cvss_avg = (
                agg_cvss_score["sum_cvss__sum"]
                / agg_total_cvss_score["total_cvss__sum"]
            )
        except ZeroDivisionError:
            cvss_avg = 0
        except TypeError:
            cvss_avg = 0
        ## Calculate vendor grade
        wt_sum = sum(
            i["wt"] for i in vendor_overview_query.values() if isinstance(i["wt"], int)
        )
        try:
            grade = wt_sum / get_grade_weight_configs("total")
        except ZeroDivisionError:
            grade = 0
        except TypeError:
            grade = 0
        ## populate last analyzed SBOM table
        most_recent_sbom = dict()
        most_recent_sbom["ven_name"] = vendor_overview_query[0]["vendorname"]
        most_recent_sbom["sbom_name"] = vendor_overview_query[0]["documentname"]
        most_recent_sbom["total_vuln"] = vendor_overview_query[0]["total_cves"]
        most_recent_sbom["severity_dist"] = [
            vendor_overview_query[0]["cve_crit"],
            vendor_overview_query[0]["cve_high"],
            vendor_overview_query[0]["cve_med"],
            vendor_overview_query[0]["cve_low"],
        ]
        ## generate values for severity distribution table
        agg_severity_dist = vendor_overview_query.aggregate(
            total_cve_crit=Sum("cve_crit"),
            total_cve_high=Sum("cve_high"),
            total_cve_med=Sum("cve_med"),
            total_cve_low=Sum("cve_low"),
        )
        vendor_severity_dist = [
            agg_severity_dist["total_cve_crit"],
            agg_severity_dist["total_cve_high"],
            agg_severity_dist["total_cve_med"],
            agg_severity_dist["total_cve_low"],
        ]
        ## populate vendor overview table
        vendorsummary_table = dict()
        vendorsummary_table["ven_name"] = query_id
        vendorsummary_table["total_sbom"] = vendor_sbom_total
        vendorsummary_table["ven_grade"] = grade
        vendorsummary_table["state"] = "selected"
        vendorsummary_table["total_vuln"] = agg_total_cves["total_cves__sum"]
        if cvss_avg == None:
            vendorsummary_table["avg_cvss"] = 0
        else:
            vendorsummary_table["avg_cvss"] = cvss_avg
        ## populate SBOM history chart
        lastyr = datetime.now() - timedelta(days=365)
        ## get parsed sbom upload time
        sbom_dates = (
            vendor_overview_query.filter(uploadtime__gt=lastyr)
            .values(
                "id",
                "uploadtime",
                month=TruncMonth("uploadtime"),
                year=TruncYear("uploadtime"),
            )
            .values("month", "year")
            .annotate(count=Count("id", distinct=True))
            .order_by("year", "month")
            .values("year", "month", "count")
        )
        ## format date vals for enumeration
        query_date_vals = {
            val_sbom["year"].strftime("%Y")
            + "-"
            + val_sbom["month"].strftime("%m"): {"count": val_sbom["count"]}
            for val_sbom in sbom_dates
        }
        ## generate list of ordered months for chart y axes
        ordered_mon_list = pd.date_range(
            lastyr, datetime.now() + timedelta(days=31), freq="M", normalize=True
        )
        ## structure to sort for chart.js sbom-history-chart in HTML template
        history_date_range = list()
        for mon in ordered_mon_list:
            dateval = mon.strftime("%Y-%m")
            if dateval in query_date_vals.keys():
                history_date_range.append(
                    {
                        "time": dateval,
                        "month": mon.strftime("%b"),
                        "year": mon.strftime("%Y"),
                        "count": query_date_vals[dateval]["count"],
                    }
                )
            else:
                history_date_range.append(
                    {
                        "time": dateval,
                        "month": mon.strftime("%b"),
                        "year": mon.strftime("%Y"),
                        "count": 0,
                    }
                )
        return {
            "all_sbom_table": vendor_overview_query,
            "most_recent_sbom": most_recent_sbom,
            "vendor_severity_dist": vendor_severity_dist,
            "vendor_sbom_total": vendor_sbom_total,
            "cvss_avg": cvss_avg,
            "ven_grade": grade,
            "vendorsummary_table": vendorsummary_table,
            "sbom_upload_history_table": history_date_range,
        }
    if type == "sbom":
        sbom_overview_query = (
            Sbom.objects.filter(id=query_id)
            .prefetch_related("cves_sbom")
            .values("id", "documentname", "vendorname", "uploadtime")
            .annotate(
                cve_crit=(
                    Count("id", filter=(Q(cves_sbom__cvss3_severity="CRITICAL")))
                ),
                cve_high=(Count("id", filter=Q(cves_sbom__cvss3_severity="HIGH"))),
                cve_med=(Count("id", filter=Q(cves_sbom__cvss3_severity="MEDIUM"))),
                cve_low=(Count("id", filter=Q(cves_sbom__cvss3_severity="LOW"))),
                total_cves=(Count("id", filter=~Q(cves_sbom__cve="na"))),
                crit_wt=get_grade_weight_configs("critical") * F("cve_crit"),
                high_wt=F("cve_high") * get_grade_weight_configs("high"),
                med_wt=F("cve_med") * get_grade_weight_configs("medium"),
                wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                sbom_grade=F("wt") / get_grade_weight_configs("total"),
                sum_cvss=(
                    Sum(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
                total_cvss=(
                    Count(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
            )
            .order_by("id")
        )
        ## handle SBOM deletion
        if len(sbom_overview_query) < 1:
            return {"sbom_err": "not_found_in_db"}
        ## format severity distribution for bar chart
        sbom_severity_dist = [
            sbom_overview_query[0]["cve_crit"],
            sbom_overview_query[0]["cve_high"],
            sbom_overview_query[0]["cve_med"],
            sbom_overview_query[0]["cve_low"],
        ]
        ## calculate cvss avg
        agg_cvss_score = sbom_overview_query.aggregate(Sum("sum_cvss"))
        try:
            cvss_avg = (
                agg_cvss_score["sum_cvss__sum"] / sbom_overview_query[0]["total_cves"]
            )
        except ZeroDivisionError:
            cvss_avg = 0
        except TypeError:
            cvss_avg = 0
        ## populate SBOM summary table
        sbomsummary_table = dict()
        sbomsummary_table["ven_name"] = sbom_overview_query[0]["vendorname"]
        sbomsummary_table["sbom_name"] = str(sbom_overview_query[0]["documentname"])
        sbomsummary_table["state"] = "selected"
        sbomsummary_table["total_vuln"] = sbom_overview_query[0]["total_cves"]
        sbomsummary_table["avg_cvss"] = cvss_avg
        sbomsummary_table["grade"] = sbom_overview_query[0]["sbom_grade"]
        sbomsummary_table["sbom_id"] = sbom_overview_query[0]["id"]
        sbomsummary_table["uploadtime"] = sbom_overview_query[0]["uploadtime"]
        return {
            "query_data": sbom_overview_query,
            "severity_dist": sbom_severity_dist,
            "sbomsummary_table": sbomsummary_table,
        }
    if type == "sbom_home":
        sbom_overview_query = (
            Sbom.objects.prefetch_related("cves_sbom")
            .values("id", "documentname", "vendorname", "uploadtime")
            .annotate(
                cve_crit=(
                    Count("id", filter=(Q(cves_sbom__cvss3_severity="CRITICAL")))
                ),
                cve_high=(Count("id", filter=Q(cves_sbom__cvss3_severity="HIGH"))),
                cve_med=(Count("id", filter=Q(cves_sbom__cvss3_severity="MEDIUM"))),
                cve_low=(Count("id", filter=Q(cves_sbom__cvss3_severity="LOW"))),
                total_cves=(Count("id", filter=~Q(cves_sbom__cve="na"))),
                total_exploits=(
                    Count("id", filter=~Q(cves_sbom__cve_exploit="exploit_not_found"))
                ),
                crit_wt=get_grade_weight_configs("critical") * F("cve_crit"),
                high_wt=F("cve_high") * get_grade_weight_configs("high"),
                med_wt=F("cve_med") * get_grade_weight_configs("medium"),
                wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                sbom_grade=F("wt") / get_grade_weight_configs("total"),
                sum_cvss=(
                    Sum(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
                total_cvss=(
                    Count(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
            )
            .order_by("-uploadtime")
        )
        if len(sbom_overview_query) < 1:
            return {"sbom_err": True}
        ## populate SBOM summary table
        sbom_table = list()
        for sbom in sbom_overview_query:
            ## calculate cvss avg
            try:
                cvss_avg = sbom["sum_cvss"] / sbom["total_cves"]
            except ZeroDivisionError:
                cvss_avg = 0
            except TypeError:
                cvss_avg = 0
            sbomsummary_table = dict()
            sbomsummary_table["ven_name"] = sbom["vendorname"]
            sbomsummary_table["sbom_name"] = sbom["documentname"]
            sbomsummary_table["total_vuln"] = sbom["total_cves"]
            sbomsummary_table["total_exploits"] = sbom["total_exploits"]
            sbomsummary_table["avg_cvss"] = cvss_avg
            sbomsummary_table["grade"] = sbom["sbom_grade"]
            sbomsummary_table["sbom_id"] = sbom["id"]
            sbomsummary_table["uploadtime"] = sbom["uploadtime"]
            sbom_table.append(sbomsummary_table)
        sbom_total = len(sbom_table)
        ## calculate overall avg grade
        agg_grade_total = sbom_overview_query.aggregate(Sum("sbom_grade"))
        try:
            avg_overall_grade = agg_grade_total["sbom_grade__sum"] / sbom_total
        except TypeError:
            avg_overall_grade = 0
        except ZeroDivisionError:
            avg_overall_grade = 0
        ## calculate avg vulns per sbom
        sum_vulns = sbom_overview_query.aggregate(Sum("total_cves"))
        total_global_vulns = sum_vulns["total_cves__sum"]
        ## get new weekly vulns
        today = date.today()
        start_week = today - timedelta(today.weekday())
        end_week = start_week + timedelta(6)
        query_new_sboms = sbom_overview_query.filter(
            uploadtime__range=[start_week, end_week]
        ).values("total_cves")
        new_weekly_vulns = query_new_sboms.aggregate(Sum("total_cves"))
        ## get avg vuln total
        try:
            avg_vuln_total = total_global_vulns / sbom_total
        except ZeroDivisionError:
            avg_vuln_total = 0
        except TypeError:
            avg_vuln_total = 0
        ## get highest risk device - format returned is (grade, vendorname, documentname)
        highest_risk_device = sbom_overview_query.values_list(
            "sbom_grade", "vendorname", "documentname"
        ).order_by("-sbom_grade")[:1]
        ## get 2 most recent SBOM uploads
        most_recent_sboms = sbom_overview_query[:2]
        return {
            "sbomsummary_table": sbom_table,
            "avg_global_grade": avg_overall_grade,
            "total_global_vulns": total_global_vulns,
            "new_weekly_vulns": new_weekly_vulns["total_cves__sum"],
            "avg_vuln_total": avg_vuln_total,
            "highest_risk_device": highest_risk_device[0],
            "most_recent_sboms": most_recent_sboms,
        }
    if type == "sbom_latest":
        sbom_overview_query = (
            Sbom.objects.order_by("-uploadtime")
            .prefetch_related("cves_sbom")
            .values("id", "documentname", "vendorname", "uploadtime")
            .annotate(
                cve_crit=(
                    Count("id", filter=(Q(cves_sbom__cvss3_severity="CRITICAL")))
                ),
                cve_high=(Count("id", filter=Q(cves_sbom__cvss3_severity="HIGH"))),
                cve_med=(Count("id", filter=Q(cves_sbom__cvss3_severity="MEDIUM"))),
                cve_low=(Count("id", filter=Q(cves_sbom__cvss3_severity="LOW"))),
                total_cves=(Count("id", filter=~Q(cves_sbom__cve="na"))),
                crit_wt=get_grade_weight_configs("critical") * F("cve_crit"),
                high_wt=F("cve_high") * get_grade_weight_configs("high"),
                med_wt=F("cve_med") * get_grade_weight_configs("medium"),
                wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                sbom_grade=F("wt") / get_grade_weight_configs("total"),
                sum_cvss=(
                    Sum(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
                total_cvss=(
                    Count(
                        "cves_sbom__cvss3_score", filter=~Q(cves_sbom__cvss3_score="na")
                    )
                ),
            )
            .first()
        )
        ## handle SBOM deletion
        try:
            if len(sbom_overview_query) < 1:
                return {"sbom_err": "not_found_in_db"}
        except TypeError:
            return {"sbom_err": "not_found_in_db"}
        ## format severity distribution for bar chart
        sbom_severity_dist = [
            sbom_overview_query["cve_crit"],
            sbom_overview_query["cve_high"],
            sbom_overview_query["cve_med"],
            sbom_overview_query["cve_low"],
        ]
        ## calculate cvss avg
        try:
            cvss_avg = (
                sbom_overview_query["sum_cvss"] / sbom_overview_query["total_cves"]
            )
        except ZeroDivisionError:
            cvss_avg = 0
        except TypeError:
            cvss_avg = 0
        ## populate SBOM summary table
        sbomsummary_table = dict()
        sbomsummary_table["ven_name"] = sbom_overview_query["vendorname"]
        sbomsummary_table["sbom_name"] = str(sbom_overview_query["documentname"])
        sbomsummary_table["state"] = "selected"
        sbomsummary_table["total_vuln"] = sbom_overview_query["total_cves"]
        sbomsummary_table["avg_cvss"] = cvss_avg
        sbomsummary_table["grade"] = sbom_overview_query["sbom_grade"]
        sbomsummary_table["sbom_id"] = sbom_overview_query["id"]
        sbomsummary_table["uploadtime"] = sbom_overview_query["uploadtime"]
        return {
            "query_data": sbom_overview_query,
            "severity_dist": sbom_severity_dist,
            "sbomsummary_table": sbomsummary_table,
        }


def getPkgAnalysis(query_id):
    package_q = (
        Package.objects.filter(sbomid_packages=query_id)
        .prefetch_related("cves_package", "cpes_package")
        .values(
            "id",
            "packagename",
            "packageversion",
            "packagesupplier",
            "packagecomment",
            "cpes_package__cpe",
            "cves_package__cve",
            "cves_package__cve_sum",
            "cves_package__cvss3_score",
            "cves_package__cve_exploit",
        )
        .annotate(
            total_cves=(
                Count("cves_package__packageid_cve", filter=~Q(cves_package__cve="na"))
            ),
        )
    )
    return package_q


def scorecardVectorQueries(vector_type, vector_query_id):
    """
    Helper function for sbomscorecard() to calculate spider chart values.
    Splits the cvss vector strings and get counts to send to spider chart.
    """
    cvss_vector_q = (
        Cve.objects.filter(sbomid_cve=vector_query_id)
        .exclude(cvss3_vector="na")
        .values("cvss3_vector")
    )
    cvss_list = list()
    spider_vals = list()
    for vector_str in cvss_vector_q:
        if len(cvss_vector_q) > 0 and str(vector_str["cvss3_vector"]).startswith(
            "CVSS:"
        ):
            cvss_split_vectors = dict(
                vec.split(":") for vec in vector_str["cvss3_vector"].lower().split("/")
            )
            cvss_list.append(cvss_split_vectors)
            net_av = [val["av"] for val in cvss_list if val["av"] == "n"]
            loc_av = [val["av"] for val in cvss_list if val["av"] == "l"]
            phys_av = [val["av"] for val in cvss_list if val["av"] == "p"]
            c = [val["c"] for val in cvss_list if val["c"] not in "n"]
            i = [val["i"] for val in cvss_list if val["i"] not in "n"]
            a = [val["a"] for val in cvss_list if val["a"] not in "n"]
            spider_vals = [
                len(net_av),
                len(loc_av),
                len(phys_av),
                len(c),
                len(i),
                len(a),
            ]
    if len(spider_vals) < 1:
        spider_vals = []
    return spider_vals


def queryTitle(lookup_id):
    """
    Queries the vendor or SBOM name as an error check for generating CSVs.
    """
    sbomname_query = Sbom.objects.filter(id=lookup_id).values("documentname")
    return sbomname_query


def genCSVData(type, db_query_data, docname):
    """
    Helper function for generating csv data. Provide data from database query
    to generate a CSV report.
    """
    if type == "vendor":
        docname = re.sub(r"[^A-Za-z0-9]", "", str(docname))
        response = HttpResponse(
            content_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename="
                + docname
                + " _vendor_summary.csv"
            },
        )
        fieldnames = {
            "documentname": "sbom_name",
            "uploadtime": "upload_date",
            "total_cves": "vulnerability_total",
            "sbom_grade": "grade",
        }
        writer = csv.DictWriter(response, fieldnames=fieldnames, extrasaction="ignore")
        writer.writerow(fieldnames)
        for i in list(db_query_data):
            writer.writerow(i)
        return response
    elif type == "sbom":
        ## check if provided docname is valid / exists and set if not
        if len(docname) == 0:
            docname = db_query_data[0]["sbomid_packages__documentname"]
        docname = re.sub(r"[^A-Za-z0-9]", "", docname)
        response = HttpResponse(
            content_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename="
                + docname
                + " _sbom_vulns.csv"
            },
        )
        fieldnames = {
            "packagename": "package_name",
            "packageversion": "package_version",
            "cves_package__cve": "cve_id",
            "cves_package__cve_sum": "cve_summary",
            "cves_package__cvss3_score": "cvss3_score",
            "cves_package__cve_exploit": "exploit_available",
            "sbomid_packages__documentname": "sbom_documentname",
            "sbomid_packages__vendorname": "vendor_name",
        }
        writer = csv.DictWriter(response, fieldnames=fieldnames, extrasaction="ignore")
        writer.writerow(fieldnames)
        for i in list(db_query_data):
            writer.writerow(i)
        return response
    elif type == "home":
        response = HttpResponse(
            content_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename="
                + docname
                + " _sbom_vulns.csv"
            },
        )
        fieldnames = {
            "ven_name": "ven_name",
            "sbom_name": "sbom_name",
            "total_vuln": "total_vuln",
            "avg_cvss": "avg_cvss",
            "grade": "grade",
            "uploadtime": "uploadtime",
        }
        writer = csv.DictWriter(response, fieldnames=fieldnames, extrasaction="ignore")
        writer.writerow(fieldnames)
        for i in db_query_data:
            writer.writerow(i)
        return response


def querySbomDropdown():
    """
    Queries all SBOMs and sorts by vendor for drop down menus.
    """
    ss_populate_dropdown = dict()
    vendor_names = Sbom.objects.values_list("vendorname", flat=True).distinct()
    vendor_values = [
        (obj.id, obj.vendorname, obj.documentname, obj.uploadtime)
        for obj in Sbom.objects.all()
    ]
    for vendor in vendor_names:
        vs_temp_list = [
            (val[0], val[2], val[3]) for val in vendor_values if val[1] == vendor
        ]
        ss_populate_dropdown[vendor] = vs_temp_list
    return ss_populate_dropdown


def queryVendorDropdown():
    """
    Queries all vendors for drop down menus.
    """
    vendor_names = Sbom.objects.values_list("vendorname", flat=True).distinct()
    return vendor_names


@login_required
def vendorscorecard(request):
    ## query to populate vendor selection dropdown
    vendor_names = Sbom.objects.values_list("vendorname", flat=True).distinct()
    ## get grade thresholds from admin config
    letterGradeThresholds = get_letter_grade_thresholds()
    ## set latest Vendor name for session
    if request.session.get("sess_latest_vendor"):
        sess_latest_vendor = request.session.get("sess_latest_vendor")
        if len(vendor_names) < 1:
            request.session["sess_latest_vendor"] = {}
            request.session.modified = True
            return render(request, "vendorscorecard.html")
        else:
            latest_vendor_upload = scorecardOverviewQueries(
                "vendor", sess_latest_vendor
            )
            ## handle deleted vendor
            if "vendor_err" in latest_vendor_upload.keys():
                query_recent_sbom = (
                    Sbom.objects.order_by("-uploadtime").values("vendorname").first()
                )
                latest_vendor_upload = scorecardOverviewQueries(
                    "vendor", query_recent_sbom["vendorname"]
                )
                request.session["sess_latest_vendor"] = latest_vendor_upload[
                    "vendorsummary_table"
                ]["ven_name"]
                request.session.modified = True
    else:
        ## LATEST - query most recent SBOM data if session cookie not set
        if len(vendor_names) < 1:
            request.session["sess_latest_vendor"] = {}
            request.session.modified = True
            return render(request, "vendorscorecard.html")
        else:
            query_recent_sbom = (
                Sbom.objects.order_by("-uploadtime").values("vendorname").first()
            )
            latest_vendor_upload = scorecardOverviewQueries(
                "vendor", query_recent_sbom["vendorname"]
            )
            request.session["sess_latest_vendor"] = latest_vendor_upload[
                "vendorsummary_table"
            ]["ven_name"]
            request.session.modified = True
    ## populate previous uploads for dropdown
    prev_uploads = getPrevUploads()
    ## check if session data stored for uploads
    current_upload_status = ""
    if request.session.get("sbom_uploads"):
        sess_upload_history = request.session.get("sbom_uploads")
        current_upload_status = request.session["sbom_uploads"]
    else:
        current_upload_status = request.session.get("sbom_uploads", False)
        request.session["sbom_uploads"] = {}
        request.session.modified = True
    ## LATEST - query vendor with most recent SBOM upload
    if request.method == "GET":
        vendor_names = queryVendorDropdown()
        return render(
            request,
            "vendorscorecard.html",
            {
                "vs_populate_dropdown": vendor_names,
                "vendorsummary_table": latest_vendor_upload["vendorsummary_table"],
                "most_recent_sbom": latest_vendor_upload["most_recent_sbom"],
                "sbom_history_table": latest_vendor_upload["sbom_upload_history_table"],
                "vendor_severity_dist": latest_vendor_upload["vendor_severity_dist"],
                "all_sbom_table": list(latest_vendor_upload["all_sbom_table"]),
                "upload_history": prev_uploads,
                "current_upload_status": current_upload_status,
                "letterGradeThresholds": letterGradeThresholds,
            },
        )
    if request.method == "POST":
        val = request.POST["select_vendor"]
        form = vendorPickerform(request.POST.get("select_vendor"))
        if form.is_valid:
            ## update session ID for queried vendor
            request.session["sess_latest_vendor"] = val
            request.session.modified = True
            ## get SBOM info sorted by vendor
            vendor_scorecard_query = scorecardOverviewQueries("vendor", val)
            return render(
                request,
                "vendorscorecard.html",
                {
                    "vs_populate_dropdown": vendor_names,
                    "vendorsummary_table": vendor_scorecard_query[
                        "vendorsummary_table"
                    ],
                    "most_recent_sbom": vendor_scorecard_query["most_recent_sbom"],
                    "sbom_history_table": vendor_scorecard_query[
                        "sbom_upload_history_table"
                    ],
                    "vendor_severity_dist": vendor_scorecard_query[
                        "vendor_severity_dist"
                    ],
                    "all_sbom_table": list(vendor_scorecard_query["all_sbom_table"]),
                    "upload_history": prev_uploads,
                    "current_upload_status": current_upload_status,
                    "letterGradeThresholds": letterGradeThresholds,
                },
            )


def login_view(request):
    """
    This function renders the login page. It verifies if a username & password
    are valid by local authentication or if they're in LDAP. Also checks if
    an AD group is assigned. If they are, the home page will be rendered.
    """
    if request.method == "POST":
        username = request.POST.get("username").strip().lower()
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            request.session["User"] = username
            login(request, user)
            logging.info(f"{username} logged in successfully")
            return redirect("home")
        else:
            messages.error(request, "Invalid username or password or not authorized")
    return render(request, "login.html", {})


@login_required
def logout_view(request):
    """
    Function for logout to redirect to login screen.
    """
    logging.info(f"{request.session['User']} logged out successfully")
    logout(request)
    return redirect("login")


@login_required
def home_view(request):
    """
    Function to render the dashboard page on template home.html.
    """
    letterGradeThresholds = get_letter_grade_thresholds()
    ## populate previous uploads for dropdown
    prev_uploads = getPrevUploads()
    ## check if session data stored for uploads
    current_upload_status = ""
    if request.session.get("sbom_uploads"):
        sess_upload_history = request.session.get("sbom_uploads")
        current_upload_status = request.session["sbom_uploads"]
    else:
        current_upload_status = request.session.get("sbom_uploads", False)
        request.session["sbom_uploads"] = {}
        request.session.modified = True
    ## added type sbom_home to scorecardOverviewQueries
    new_q = scorecardOverviewQueries("sbom_home", 0)
    ## generates CSV report for export button. This contains the summary table of all sboms that is displayed on the homepage
    if "gen_homecsv" in request.POST:
        today = date.today()
        name = str(today) + "_sboms"
        home_csv = genCSVData("home", new_q["sbomsummary_table"], name)
        return home_csv
    try:
        if new_q["sbom_err"]:
            return render(request, "home.html")
    except KeyError:
        return render(
            request,
            "home.html",
            {
                "sbom_overview_query": new_q["sbomsummary_table"],
                "avg_global_grade": new_q["avg_global_grade"],
                "total_global_vulns": new_q["total_global_vulns"],
                "new_weekly_vulns": new_q["new_weekly_vulns"],
                "avg_vuln_total": new_q["avg_vuln_total"],
                "highest_risk_device": new_q["highest_risk_device"],
                "most_recent_sboms": new_q["most_recent_sboms"],
                "upload_history": prev_uploads,
                "current_upload_status": current_upload_status,
                "letterGradeThresholds": letterGradeThresholds,
            },
        )


def check_upload(hash, fname):
    """
    Submits job to django-rq to follow sbom_process upload
    """
    queue = django_rq.get_queue("default")
    return queue.enqueue(
        check_log_file, hash, fname, job_timeout=180, meta={"sbom_filename": fname}
    )


@login_required
def sbomscorecard(request):
    """
    Function to render the sbom scorecard page on template sbomscorecard.html.
    """
    ## setup general request data
    uploadform = SbomForm()
    ## query to populate sbom dropdown
    ss_populate_dropdown = querySbomDropdown()
    ## query admin config for grade thresholds
    letterGradeThresholds = get_letter_grade_thresholds()
    ## set latest SBOM ID for session
    if request.session.get("sess_latest_sbom"):
        sess_latest_sbom = request.session.get("sess_latest_sbom")
        latest_sbom_upload = scorecardOverviewQueries("sbom", sess_latest_sbom)
        ## handle deleted SBOMs
        if "sbom_err" in latest_sbom_upload.keys():
            latest_sbom_upload = scorecardOverviewQueries("sbom_latest", "0")
            try:
                if latest_sbom_upload["sbom_err"]:
                    return render(request, "sbomscorecard.html")
            except KeyError:
                request.session["sess_latest_sbom"] = {}
                request.session.modified = True
    else:
        ## LATEST - query most recent SBOM data
        latest_sbom_upload = scorecardOverviewQueries("sbom_latest", "0")
        try:
            if latest_sbom_upload["sbom_err"]:
                request.session["sess_latest_sbom"] = {}
                request.session.modified = True
            else:
                request.session["sess_latest_sbom"] = latest_sbom_upload[
                    "sbomsummary_table"
                ]["sbom_id"]
                request.session.modified = True
        except KeyError:
            logger.info(
                f"No SBOMs available in database to set session cookie item. Setting session item as empty."
            )
            request.session["sess_latest_sbom"] = {}
            request.session.modified = True
    ## Populate previous uploads for dropdown
    prev_uploads = getPrevUploads()
    ## Check if session data stored for uploads
    current_upload_status = ""
    if request.session.get("sbom_uploads"):
        sess_upload_history = request.session.get("sbom_uploads")
        current_upload_status = request.session["sbom_uploads"]
    else:
        current_upload_status = request.session.get("sbom_uploads", False)
        request.session["sbom_uploads"] = {}
        request.session.modified = True
    ## LATEST - query most recent SBOM data
    if len(request.session["sess_latest_sbom"]) < 1:
        latest_sbom_severity_dist = 0
        latest_sbomsummary_table = []
        latest_spider_vals = []
        latest_package_q = []
        latest_package_q_dc = []
        latest_cve_q = []
    else:
        ## LATEST - populate SBOM severity distribution chart from function results
        latest_sbom_severity_dist = latest_sbom_upload["severity_dist"]
        ## LATEST - populate SBOM Analysis table from function results
        latest_sbomsummary_table = latest_sbom_upload["sbomsummary_table"]
        ## LATEST - populate CVSS vector spider chart from function
        latest_spider_vals = scorecardVectorQueries(
            "sbom", latest_sbom_upload["sbomsummary_table"]["sbom_id"]
        )
        ## LATEST - general query to populate package and vulnerability detail table
        latest_package_q = getPkgAnalysis(
            latest_sbom_upload["sbomsummary_table"]["sbom_id"]
        )
        ## LATEST - subquery to populate package table
        latest_package_q_dc = latest_package_q.values(
            "id",
            "packagename",
            "packageversion",
            "packagesupplier",
            "packagecomment",
            "cpes_package__cpe",
            "total_cves",
        ).distinct()
        ## LATEST - subquery to populate vulnerability table
        latest_cve_q = (
            latest_package_q.exclude(cves_package__cve="na")
            .values(
                "id",
                "packagename",
                "packageversion",
                "cves_package__cve",
                "cves_package__cve_sum",
                "cves_package__cvss3_score",
                "cves_package__cve_exploit",
            )
            .order_by("id")
        )
    if request.method == "GET":
        return render(
            request,
            "sbomscorecard.html",
            {
                "ss_populate_dropdown": ss_populate_dropdown,
                "sbomsummary_table": latest_sbomsummary_table,
                "form": uploadform,
                "severity_dist_chart": latest_sbom_severity_dist,
                "spider_vals": latest_spider_vals,
                "package_table": list(latest_package_q_dc),
                "cve_table": list(latest_cve_q),
                "upload_history": prev_uploads,
                "current_upload_status": current_upload_status,
                "letterGradeThresholds": letterGradeThresholds,
            },
        )
    ## Form to upload SBOM for anaylsis
    if request.method == "POST":
        if "uploaded_sbom" in request.FILES:
            uploadform = SbomForm(request.POST, request.FILES)
            sbomfiles = request.FILES.getlist("uploaded_sbom")
            upload_jobs = list()
            if uploadform.is_valid():
                for file in sbomfiles:
                    sbomfile = SbomUpload(sbomfile=file, filename=file.name)
                    sbomfile.save()
                    hash_query = (
                        SbomUpload.objects.filter(filename=file)
                        .order_by("uploadtime")
                        .values("sha1")
                        .last()
                    )
                    job = check_upload(hash_query["sha1"], file.name)
                    upload_jobs.append(job.id)
                    sbomfile.job_id = job.id
                    sbomfile.save()
                    logger.info(
                        f"Sent upload job ID: {job.id}, sbomfile_sha1: {hash_query['sha1']}"
                    )
                messages.success(
                    request,
                    "SBOM file(s) uploaded and queued. Check Uploads Status menu for progress.",
                )
                if "upload_queue" not in request.session["sbom_uploads"]:
                    request.session["sbom_uploads"]["upload_queue"] = upload_jobs
                else:
                    session_queue = request.session["sbom_uploads"]["upload_queue"]
                    ## only add new jobs to queue
                    check = [
                        new_job
                        for new_job in upload_jobs
                        if new_job not in set(session_queue)
                    ]
                    if len(check) > 0:
                        for new_job in check:
                            session_queue.append(new_job)
                            request.session["sbom_uploads"][
                                "upload_queue"
                            ] = session_queue
                request.session.modified = True
            return render(
                request,
                "sbomscorecard.html",
                {
                    "ss_populate_dropdown": ss_populate_dropdown,
                    "sbomsummary_table": latest_sbomsummary_table,
                    "severity_dist_chart": latest_sbom_severity_dist,
                    "spider_vals": latest_spider_vals,
                    "package_table": list(latest_package_q_dc),
                    "cve_table": list(latest_cve_q),
                    "upload_history": prev_uploads,
                    "current_upload_status": current_upload_status,
                    "letterGradeThresholds": letterGradeThresholds,
                },
            )
        ## handle selectmenu POST to select SBOM for viewing
        elif "select_sbom" in request.POST:
            select_sbom = request.POST["select_sbom"]
            form = vendorPickerform(request.POST.get("select_vendor"))
            ## validate form
            if form.is_valid:
                ## update session id for queried SBOM
                request.session["sess_latest_sbom"] = select_sbom
                request.session.modified = True
                ## call function to get most SBOM data
                sbom_data_query = scorecardOverviewQueries("sbom", select_sbom)
                ## populate SBOM severity distribution chart from function results
                sbom_severity_dist = sbom_data_query["severity_dist"]
                ## populate SBOM Analysis table from function results
                sbomsummary_table = sbom_data_query["sbomsummary_table"]
                ## populate CVSS vector spider chart from function
                spider_vals = scorecardVectorQueries("sbom", select_sbom)
                ## general query to populate package and vulnerability detail table
                package_q = getPkgAnalysis(select_sbom)
                ## subquery to populate package table
                package_q_dc = package_q.values(
                    "id",
                    "packagename",
                    "packageversion",
                    "packagesupplier",
                    "packagecomment",
                    "cpes_package__cpe",
                    "total_cves",
                ).distinct()
                ## subquery to populate vulnerability table
                cve_q = (
                    package_q.exclude(cves_package__cve="na")
                    .values(
                        "id",
                        "packagename",
                        "packageversion",
                        "cves_package__cve",
                        "cves_package__cve_sum",
                        "cves_package__cvss3_score",
                        "cves_package__cve_exploit",
                    )
                    .order_by("id")
                )
            else:
                headerMsg = "404 Not Found"
                bodyMsg = "The page requested cannot be found."
                context = {"headerMsg": headerMsg, "bodyMsg": bodyMsg}
                return render(request, "not-found-page.html", context)
    return render(
        request,
        "sbomscorecard.html",
        {
            "ss_populate_dropdown": ss_populate_dropdown,
            "sbomsummary_table": sbomsummary_table,
            "form": uploadform,
            "severity_dist_chart": sbom_severity_dist,
            "spider_vals": spider_vals,
            "package_table": list(package_q_dc),
            "cve_table": list(cve_q),
            "upload_history": prev_uploads,
            "current_upload_status": current_upload_status,
            "letterGradeThresholds": letterGradeThresholds,
        },
    )


# TODO: fix input validation
@login_required
def genreport(request):
    """
    Function to handle the SBOM csv export. If post request contains
    'gen_sbomcsv' then generate am SBOM csv for sbomscorecard page. If
    gen_vendorcsv in the post request then a vendor specific csv export is
    generated.
    """
    if "gen_sbomcsv" in request.POST:
        select_sbom = request.POST["gen_sbomcsv"]
        ## call fxn to generate sbom vulnerability details
        cve_q = scorecardCSVQueries("sbom", select_sbom)
        ## check if db query returned data for SBOM and set document name, if not
        if len(cve_q) == 0:
            query_name_result = queryTitle(select_sbom)[0]["documentname"]
            docname = query_name_result
        else:
            docname = cve_q[0]["sbomid_packages__documentname"]
        ## call fxn to generate SBOM CSV
        sbom_csv = genCSVData("sbom", cve_q, docname)
        return sbom_csv
    ## handle vendor csv export
    elif "gen_vendorcsv" in request.POST:
        select_vendor = request.POST["gen_vendorcsv"]
        ## call fxn to generate vendor results
        query_ven_sbomsummary = scorecardCSVQueries("vendor", select_vendor)
        ## call fxn to generate vendor CSV
        vendor_csv = genCSVData("vendor", query_ven_sbomsummary, str(select_vendor))
        return vendor_csv
    ## handle other, invalid requests
    else:
        headerMsg = "400 Bad Request"
        bodyMsg = "Your request resulted in an error."
        context = {"headerMsg": headerMsg, "bodyMsg": bodyMsg}
        return render(request, "not-found-page.html", context)


def error_404(request, exception):
    """
    Results the 404 error message on not-found-page.html template.
    """
    headerMsg = "404 Not Found"
    bodyMsg = "The page requested cannot be found."
    context = {"headerMsg": headerMsg, "bodyMsg": bodyMsg}
    return render(request, "not-found-page.html", context)


def error_500(request):
    """
    Results the 500 error message on not-found-page.html template.
    """
    headerMsg = "500 Server Error"
    bodyMsg = "The server encountered an internal error."
    context = {"headerMsg": headerMsg, "bodyMsg": bodyMsg}
    return render(request, "not-found-page.html", context)


def error_403(request, exception):
    """
    Results the 403 error message on not-found-page.html template.
    """
    headerMsg = "403 HTTP Forbidden"
    bodyMsg = "Sorry, you cannot access this page."
    context = {"headerMsg": headerMsg, "bodyMsg": bodyMsg}
    return render(request, "not-found-page.html", context)


def error_400(request, exception):
    """
    Results the 400 error message on not-found-page.html template.
    """
    headerMsg = "400 Bad Request"
    bodyMsg = "Your request resulted in an error."
    context = {"headerMsg": headerMsg, "bodyMsg": bodyMsg}
    return render(request, "not-found-page.html", context)
