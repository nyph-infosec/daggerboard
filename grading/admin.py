from django.contrib import admin

from .models import GradeThresholds, GradeWeights


@admin.register(GradeWeights)
class GradingWeightsAdmin(admin.ModelAdmin):
    list_display = ["crit_weight", "high_weight", "medium_weight", "low_weight"]

    def has_add_permission(self, request):
        return (
            False
            if self.model.objects.count() > 0
            else super().has_add_permission(request)
        )


@admin.register(GradeThresholds)
class GradingThresholdsAdmin(admin.ModelAdmin):
    fields = (
        "less_than_threshold_grade_A",
        ("greater_eq_threshold_grade_B", "less_than_threshold_grade_B"),
        ("greater_eq_threshold_grade_C", "less_than_threshold_grade_C"),
        ("greater_eq_threshold_grade_D", "less_than_threshold_grade_D"),
        "greater_eq_threshold_grade_F",
    )
    list_display = [
        "less_than_threshold_grade_A",
        "greater_eq_threshold_grade_B",
        "less_than_threshold_grade_B",
        "greater_eq_threshold_grade_C",
        "less_than_threshold_grade_C",
        "greater_eq_threshold_grade_D",
        "less_than_threshold_grade_D",
        "greater_eq_threshold_grade_F",
    ]

    def has_add_permission(self, request):
        return (
            False
            if self.model.objects.count() > 0
            else super().has_add_permission(request)
        )
