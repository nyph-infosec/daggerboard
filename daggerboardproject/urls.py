# SPDX-FileCopyrightText: 2022 NewYork-Presbyterian Hospital
#
# SPDX-License-Identifier: MIT

"""daggerboard URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

from apps.daggerboard_ui.views import (APILoginView, error_400, error_403,
                                       error_404, error_500, genreport,
                                       home_view, login_view, logout_view,
                                       sbomscorecard, upload_status,
                                       uploadProgressChk, vendorscorecard)
from apps.sbomscanner.views import DaggerBoardAPIView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("", home_view, name="home"),
    path("vendorscorecard/", vendorscorecard, name="vendor_scorecard"),
    path("sbomscorecard/", sbomscorecard, name="sbom_scorecard"),
    path("genreport/", genreport, name="genreport"),
    path("uploadstatus/", uploadProgressChk.as_view(), name="mjob_status"),
    path("sbomuploadstatus/", upload_status, name="upload_status"),
    path("django-rq/", include("django_rq.urls")),
    path("api/sbom/", DaggerBoardAPIView.as_view(), name="daggerboard_api"),
    path(
        "api/sbom/<str:transaction_id>/",
        DaggerBoardAPIView.as_view(),
        name="daggerboard_api_with_id",
    ),
    path("api/login/", APILoginView.as_view(), name="daggerboard_api_login"),
]

handler404 = error_404
handler500 = error_500
handler403 = error_403
handler400 = error_400

admin.site.site_header = "DaggerBoard Admin"
admin.site.site_title = "DaggerBoard Admin Portal"
admin.site.index_title = "Welcome to DaggerBoard Admin Portal"
