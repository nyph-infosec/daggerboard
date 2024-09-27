import logging
from datetime import date, datetime, timedelta

import pandas as pd
from django.db.models import Count, F, Q, Sum
from django.db.models.functions import TruncMonth, TruncYear

from apps.daggerboard_ui.models import Sbom
from apps.grading.models import GradeWeights


class ScorecardCalculations:
    def __init__(self):
        pass

    def get_grade_weight_configs(self, risk_type):
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
            logging.info(f"{e} - Invalid score type requested")

    def get_letter_grade(self, score):
        """If less than 2, grade is A, if less than 4, grade is B, if less than 6, grade is C, if less than 8, grade is D."""
        grade_thresholds = {
            "A": (0, 2),
            "B": (2, 4),
            "C": (4, 6),
            "D": (6, 8),
            "F": (8, 1000),
        }
        for grade, (lower, upper) in grade_thresholds.items():
            if lower <= score < upper:
                return grade
        return "Invalid score"

    # TODO - Refactor this function to be more modular
    def scorecardOverviewQueries(self, type, query_id):  # noqa
        """
        Type can be "vendor", "sbom", "sbom_home", "sbom_latest"
        """
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
                        Count(
                            "id", filter=~Q(cves_sbom__cve_exploit="exploit_not_found")
                        )
                    ),
                    crit_wt=40 * F("cve_crit"),
                    high_wt=F("cve_high") * 10,
                    med_wt=F("cve_med") * 3,
                    wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                    sbom_grade=F("wt") / self.get_grade_weight_configs("total"),
                    sum_cvss=(
                        Sum(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                    total_cvss=(
                        Count(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                )
                .order_by("uploadtime")
            )
            # handle SBOM deletion
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
            # Calculate vendor grade
            wt_sum = sum(
                i["wt"]
                for i in vendor_overview_query.values()
                if isinstance(i["wt"], int)
            )
            try:
                grade = wt_sum / self.get_grade_weight_configs("total")
            except ZeroDivisionError:
                grade = 0
            except TypeError:
                grade = 0
            # populate last analyzed SBOM table
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
            # generate values for severity distribution table
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
            # populate vendor overview table
            vendorsummary_table = dict()
            vendorsummary_table["ven_name"] = query_id
            vendorsummary_table["total_sbom"] = vendor_sbom_total
            vendorsummary_table["ven_grade"] = grade
            vendorsummary_table["state"] = "selected"
            vendorsummary_table["total_vuln"] = agg_total_cves["total_cves__sum"]
            if cvss_avg is None:
                vendorsummary_table["avg_cvss"] = 0
            else:
                vendorsummary_table["avg_cvss"] = cvss_avg
            # populate SBOM history chart
            lastyr = datetime.now() - timedelta(days=365)
            # get parsed sbom upload time
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
            # format date vals for enumeration
            query_date_vals = {
                val_sbom["year"].strftime("%Y")
                + "-"
                + val_sbom["month"].strftime("%m"): {"count": val_sbom["count"]}
                for val_sbom in sbom_dates
            }
            # generate list of ordered months for chart y axes
            ordered_mon_list = pd.date_range(
                lastyr, datetime.now() + timedelta(days=31), freq="M", normalize=True
            )
            # structure to sort for chart.js sbom-history-chart in HTML template
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
                    crit_wt=self.get_grade_weight_configs("critical") * F("cve_crit"),
                    high_wt=F("cve_high") * self.get_grade_weight_configs("high"),
                    med_wt=F("cve_med") * self.get_grade_weight_configs("medium"),
                    wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                    sbom_grade=F("wt") / self.get_grade_weight_configs("total"),
                    sum_cvss=(
                        Sum(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                    total_cvss=(
                        Count(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                )
                .order_by("id")
            )
            # handle SBOM deletion
            if len(sbom_overview_query) < 1:
                return {"sbom_err": "not_found_in_db"}
            # format severity distribution for bar chart
            sbom_severity_dist = {
                "Critical": sbom_overview_query[0]["cve_crit"],
                "High": sbom_overview_query[0]["cve_high"],
                "Medium": sbom_overview_query[0]["cve_med"],
                "Low": sbom_overview_query[0]["cve_low"],
            }
            # calculate cvss avg
            agg_cvss_score = sbom_overview_query.aggregate(Sum("sum_cvss"))
            try:
                cvss_avg = (
                    agg_cvss_score["sum_cvss__sum"]
                    / sbom_overview_query[0]["total_cves"]
                )
            except ZeroDivisionError:
                cvss_avg = 0
            except TypeError:
                cvss_avg = 0
            # populate SBOM summary table
            sbomsummary_table = dict()
            sbomsummary_table["ven_name"] = sbom_overview_query[0]["vendorname"]
            sbomsummary_table["sbom_name"] = str(sbom_overview_query[0]["documentname"])
            sbomsummary_table["state"] = "selected"
            sbomsummary_table["total_vuln"] = sbom_overview_query[0]["total_cves"]
            sbomsummary_table["avg_cvss"] = cvss_avg
            sbomsummary_table["grade"] = sbom_overview_query[0]["sbom_grade"]
            sbomsummary_table["sbom_id"] = sbom_overview_query[0]["id"]
            sbomsummary_table["uploadtime"] = sbom_overview_query[0]["uploadtime"]
            sbomsummary_table["letter_grade"] = self.get_letter_grade(
                score=sbomsummary_table["grade"]
            )
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
                        Count(
                            "id", filter=~Q(cves_sbom__cve_exploit="exploit_not_found")
                        )
                    ),
                    crit_wt=self.get_grade_weight_configs("critical") * F("cve_crit"),
                    high_wt=F("cve_high") * self.get_grade_weight_configs("high"),
                    med_wt=F("cve_med") * self.get_grade_weight_configs("medium"),
                    wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                    sbom_grade=F("wt") / self.get_grade_weight_configs("total"),
                    sum_cvss=(
                        Sum(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                    total_cvss=(
                        Count(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                )
                .order_by("-uploadtime")
            )
            if len(sbom_overview_query) < 1:
                return {"sbom_err": True}
            # populate SBOM summary table
            sbom_table = list()
            for sbom in sbom_overview_query:
                # calculate cvss avg
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
            # calculate overall avg grade
            agg_grade_total = sbom_overview_query.aggregate(Sum("sbom_grade"))
            try:
                avg_overall_grade = agg_grade_total["sbom_grade__sum"] / sbom_total
            except TypeError:
                avg_overall_grade = 0
            except ZeroDivisionError:
                avg_overall_grade = 0
            # calculate avg vulns per sbom
            sum_vulns = sbom_overview_query.aggregate(Sum("total_cves"))
            total_global_vulns = sum_vulns["total_cves__sum"]
            # get new weekly vulns
            today = date.today()
            start_week = today - timedelta(today.weekday())
            end_week = start_week + timedelta(6)
            query_new_sboms = sbom_overview_query.filter(
                uploadtime__range=[start_week, end_week]
            ).values("total_cves")
            new_weekly_vulns = query_new_sboms.aggregate(Sum("total_cves"))
            # get avg vuln total
            try:
                avg_vuln_total = total_global_vulns / sbom_total
            except ZeroDivisionError:
                avg_vuln_total = 0
            except TypeError:
                avg_vuln_total = 0
            # get highest risk device - format returned is (grade, vendorname, documentname)
            highest_risk_device = sbom_overview_query.values_list(
                "sbom_grade", "vendorname", "documentname"
            ).order_by("-sbom_grade")[:1]
            # get 2 most recent SBOM uploads
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
                    total_cves=(
                        Count("id", filter=~Q(cves_sbom__cve="na"))
                    ),  # TODO remove. THis is not being used.
                    crit_wt=self.get_grade_weight_configs("critical") * F("cve_crit"),
                    high_wt=F("cve_high") * self.get_grade_weight_configs("high"),
                    med_wt=F("cve_med") * self.get_grade_weight_configs("medium"),
                    wt=F("crit_wt") + F("high_wt") + F("med_wt") + F("cve_low"),
                    sbom_grade=F("wt") / self.get_grade_weight_configs("total"),
                    sum_cvss=(
                        Sum(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                    total_cvss=(
                        Count(
                            "cves_sbom__cvss3_score",
                            filter=~Q(cves_sbom__cvss3_score="na"),
                        )
                    ),
                )
                .first()
            )
            # handle SBOM deletion
            try:
                if len(sbom_overview_query) < 1:
                    return {"sbom_err": "not_found_in_db"}
            except TypeError:
                return {"sbom_err": "not_found_in_db"}
            # format severity distribution for bar chart
            sbom_severity_dist = {
                "Critical": sbom_overview_query[0]["cve_crit"],
                "High": sbom_overview_query[0]["cve_high"],
                "Medium": sbom_overview_query[0]["cve_med"],
                "Low": sbom_overview_query[0]["cve_low"],
            }
            # calculate cvss avg
            try:
                cvss_avg = (
                    sbom_overview_query["sum_cvss"] / sbom_overview_query["total_cves"]
                )
            except ZeroDivisionError:
                cvss_avg = 0
            except TypeError:
                cvss_avg = 0
            # populate SBOM summary table
            sbomsummary_table = dict()
            sbomsummary_table["ven_name"] = sbom_overview_query["vendorname"]
            sbomsummary_table["sbom_name"] = str(sbom_overview_query["documentname"])
            sbomsummary_table["state"] = "selected"
            sbomsummary_table["total_vuln"] = sbom_overview_query["total_cves"]
            sbomsummary_table["avg_cvss"] = cvss_avg
            sbomsummary_table["grade"] = sbom_overview_query["sbom_grade"]
            sbomsummary_table["sbom_id"] = sbom_overview_query["id"]
            sbomsummary_table["uploadtime"] = sbom_overview_query["uploadtime"]
            sbomsummary_table["letter_grade"] = self.get_letter_grade(
                score=sbomsummary_table["grade"]
            )
            return {
                "query_data": sbom_overview_query,
                "severity_dist": sbom_severity_dist,
                "sbomsummary_table": sbomsummary_table,
            }
