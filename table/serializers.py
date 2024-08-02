from rest_framework import serializers
from .models import Total

class TotalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Total 
        fields = '__all__'  
