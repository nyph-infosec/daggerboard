from rest_framework import serializers

from .models import DaggerBoardAPI


class SbomSerializer(serializers.ModelSerializer):
    class Meta:
        model = DaggerBoardAPI
        fields = "__all__"
