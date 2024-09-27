from django.db import models


class DaggerBoardAPI(models.Model):
    """
    Model for holding data specific to SBOMs uploaded.
    """

    id = models.AutoField(primary_key=True)
    documentname = models.CharField(max_length=200)
    vendorname = models.CharField(max_length=100)
    critical_risk_count = models.IntegerField()
    high_risk_count = models.IntegerField()
    medium_risk_count = models.IntegerField()
    low_risk_count = models.IntegerField()
    risk_grade = models.TextField()
    created_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.documentname}"
