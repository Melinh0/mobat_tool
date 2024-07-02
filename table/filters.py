from enum import Enum
from django.conf import settings

class TableChoice(Enum):
    PRIMEIRO_SEMESTRE = 'PrimeiroSemestre'
    SEGUNDO_SEMESTRE = 'SegundoSemestre'
    TERCEIRO_SEMESTRE = 'TerceiroSemestre'
    TOTAL = 'Total'

    @classmethod
    def choices(cls):
        return [(key.name, key.value) for key in cls]

    @classmethod
    def get_db_path(cls, choice):
        databases = settings.DATABASES
        
        mapping = {
            'PrimeiroSemestre': databases['PrimeiroSemestre']['NAME'],
            'SegundoSemestre': databases['SegundoSemestre']['NAME'],
            'TerceiroSemestre': databases['TerceiroSemestre']['NAME'],
            'Total': databases['Total']['NAME'],
        }
        
        return mapping.get(choice)
