import logging
import os

from celery.result import AsyncResult
from django.conf import settings
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

from apps.sbomscanner.models import DaggerBoardAPI
from apps.sbomscanner.serializers import SbomSerializer
from apps.sbomscanner.tasks import run_sbomscanner

logging.basicConfig(level=logging.INFO)


class DaggerBoardAPIView(APIView):
    """
    API View for DaggerBoard. Handles GET and POST requests.

    Authentication is required and throttling is applied on a per-user basis.
    """

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["documentname", "vendorname"]
    ordering_fields = ["documentname", "vendorname"]

    def get(self, request, transaction_id=None):
        """
        Handles GET requests. Returns the DaggerBoardAPI object with the given transaction ID,
        or all DaggerBoardAPI objects if no transaction ID is provided.

        Args:
            request (HttpRequest): The request that triggered this method.
            transaction_id (int, optional): The ID of the DaggerBoardAPI object to retrieve.

        Returns:
            Response: A Response object with serialized DaggerBoardAPI data.
        """
        if transaction_id is not None:
            task = AsyncResult(transaction_id)
            if task.state == "PENDING":
                return Response(
                    {"status": "Task is still processing"},
                    status=status.HTTP_202_ACCEPTED,
                )
            elif task.state != "SUCCESS":
                return Response(
                    {"error": "Task did not complete successfully"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            elif task.state == "SUCCESS":
                model_id = task.result
                model = DaggerBoardAPI.objects.filter(id=model_id).first()
                if model is None:
                    return Response(
                        {"error": "No such transaction ID"},
                        status=status.HTTP_404_NOT_FOUND,
                    )
                serializer = SbomSerializer(model)
                return Response(serializer.data)
            else:
                model_id = task.result
                model = DaggerBoardAPI.objects.filter(id=model_id).first()
                if model is None:
                    return Response(
                        {"error": "No such transaction ID"},
                        status=status.HTTP_404_NOT_FOUND,
                    )
                serializer = SbomSerializer(model)
                return Response(serializer.data)
        else:
            models = DaggerBoardAPI.objects.all()
            for backend in list(self.filter_backends):  # For Filtering capabilities
                models = backend().filter_queryset(request, models, self)
            serializer = SbomSerializer(models, many=True)
            return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests. Processes an uploaded SBOM file.
        """
        logging.info("POST method started")
        sbom_file = request.data.get("file")
        if sbom_file is not None:
            logging.info("File upload started")
            file_path = os.path.join(
                settings.BASE_DIR,
                "apps",
                "sbomscanner",
                "uploads",
                "sbom",
                sbom_file.name,
            )
            with open(file_path, "wb+") as destination:
                for chunk in sbom_file.chunks():
                    destination.write(chunk)
            logging.info("File upload ended")
            task = run_sbomscanner.delay(file_path)
            return Response(
                {"transaction_id": str(task.id)}, status=status.HTTP_201_CREATED
            )
        else:
            logging.error("No file provided")
            return Response(
                {"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST
            )
