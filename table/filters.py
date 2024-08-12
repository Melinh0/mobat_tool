from enum import Enum
from django.conf import settings

class TableChoice(Enum):
    TOTAL = 'Total'
    DEFAULT = 'default'

    @classmethod
    def choices(cls):
        return [(key.name, key.value) for key in cls]

    @classmethod
    def get_db_path(cls, choice):
        databases = settings.DATABASES
        mapping = {
            'Total': databases['Total']['NAME'],
            'default': databases['default']['NAME'],
        }
        return mapping.get(choice)
