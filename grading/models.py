# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

from django.db import models


class GradeWeights(models.Model):
    """
    Model for holding risk score weights for grading calculation

    Default weight scores:
        Critical Weight Score: 40
        High Weight Score: 10
        Medium Weight Score: 3
        Low Weight Score: 1
    """

    id = models.AutoField(primary_key=True)
    crit_weight = models.IntegerField(
        default=40,
        verbose_name="Critical Weight Score",
        help_text="Critical weight score",
    )
    high_weight = models.IntegerField(
        default=10,
        verbose_name="High Weight Score",
        help_text="High weight score",
    )
    medium_weight = models.IntegerField(
        default=3,
        verbose_name="Medium Weight Score",
        help_text="Medium weight score",
    )
    low_weight = models.IntegerField(
        default=1,
        verbose_name="Low Weight Score",
        help_text="Low weight score",
    )

    def __str__(self):
        return "Policy for Grade Weight"

    class Meta:
        verbose_name_plural = "Grade Weights"
        app_label = "grading"


class GradeThresholds(models.Model):

    """
    Model for holding thresholds for letter grades.

    Default thresholds:
        A score less than 2 = A
        A score greater equal 2 and less than 4 = B
        A score greater equal 4 and less than 6 = C
        A score greater equal 6 and less than 8 = D
        A score greater than 8 = F
    """

    id = models.AutoField(primary_key=True)
    less_than_threshold_grade_A = models.IntegerField(
        default=2,
        verbose_name="Letter Grade A - Less than",
        help_text="Any score less than this will result in a letter grade of A",
    )
    greater_eq_threshold_grade_B = models.IntegerField(
        default=2,
        verbose_name="Letter Grade B - Greater or equal to",
        help_text="Any score greater than this will result in a letter grade of B",
    )
    less_than_threshold_grade_B = models.IntegerField(
        default=4,
        verbose_name="and less than",
        help_text="Any score less than this will result in a Letter Grade of B",
    )
    greater_eq_threshold_grade_C = models.IntegerField(
        default=4,
        verbose_name="Letter Grade C - Greater or Equal To",
        help_text="Any score greater than this will result in a letter Grade of C",
    )
    less_than_threshold_grade_C = models.IntegerField(
        default=6,
        verbose_name="and less than",
        help_text="Any score less than this will result in a letter Grade of C",
    )
    greater_eq_threshold_grade_D = models.IntegerField(
        default=6,
        verbose_name="Letter Grade D - Greater or Equal To",
        help_text="Any score greater than this will result in a letter Grade of D",
    )
    less_than_threshold_grade_D = models.IntegerField(
        default=8,
        verbose_name="and less than",
        help_text="Any score less than this will result in a letter Grade of D",
    )
    greater_eq_threshold_grade_F = models.IntegerField(
        default=8,
        verbose_name="Letter Grade F - Greater Than",
        help_text="Any score greater than this will result in a letter Grade of F",
    )

    def __str__(self):
        return "Policy for Grade Thresholds"

    class Meta:
        verbose_name_plural = "Letter Grade Thresholds"
        app_label = "grading"
