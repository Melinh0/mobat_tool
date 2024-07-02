from django.contrib import admin
from .models import PrimeiroSemestre, SegundoSemestre, TerceiroSemestre, Total

admin.site.register(PrimeiroSemestre)
admin.site.register(SegundoSemestre)
admin.site.register(TerceiroSemestre)
admin.site.register(Total)
