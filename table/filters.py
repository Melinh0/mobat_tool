from enum import Enum

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
        mapping = {
            'PrimeiroSemestre': 'table/Seasons/PrimeiroSemestre.sqlite',
            'SegundoSemestre': 'table/Seasons/SegundoSemestre.sqlite',
            'TerceiroSemestre': 'table/Seasons/TerceiroSemestre.sqlite',
            'Total': 'table/Seasons/Total.sqlite',
        }
        return mapping.get(choice)
