# Create your tasks here

from celery import shared_task
from celery.utils.log import get_task_logger

from apps.sbomscanner.models import DaggerBoardAPI
from apps.sbomscanner.sbom_process import SbomScanner

logger = get_task_logger(__name__)


@shared_task
def run_sbomscanner(sbom_file_path):
    sbomscanner = SbomScanner()
    results = sbomscanner.main()
    model = DaggerBoardAPI.objects.create(
        documentname=results.get("daggerboard_scorecard")
        .query_data[0]
        .get("documentname"),
        vendorname=results.get("daggerboard_scorecard").query_data[0].get("vendorname"),
        critical_risk_count=results.get("daggerboard_scorecard")
        .query_data[0]
        .get("cve_crit"),
        high_risk_count=results.get("daggerboard_scorecard")
        .query_data[0]
        .get("cve_high"),
        medium_risk_count=results.get("daggerboard_scorecard")
        .query_data[0]
        .get("cve_med"),
        low_risk_count=results.get("daggerboard_scorecard")
        .query_data[0]
        .get("cve_low"),
        risk_grade=results.get("daggerboard_scorecard").sbomsummary_table.get(
            "letter_grade"
        ),
    )
    return model.id
