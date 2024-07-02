from rest_framework import serializers
from .models import PrimeiroSemestre, SegundoSemestre, TerceiroSemestre, Total

class PrimeiroSemestreSerializer(serializers.ModelSerializer):
    class Meta:
        model = PrimeiroSemestre  
        fields = '__all__'  

class SegundoSemestreSerializer(serializers.ModelSerializer):
    class Meta:
        model = SegundoSemestre  
        fields = '__all__' 

class TerceiroSemestreSerializer(serializers.ModelSerializer):
    class Meta:
        model = TerceiroSemestre 
        fields = '__all__'  

class TotalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Total 
        fields = '__all__'  
