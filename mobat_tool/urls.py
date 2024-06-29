from django.contrib import admin
from django.urls import path, include  
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="MoBAt Tool",
        default_version="v1",
        description="API for managing graphs based on five Cyber Threat Modeling bases and IP threat monitoring",
        contact=openapi.Contact(email="jonas.nogueira@aluno.uece.br"),
    ),
    public=True,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    path('api/', include('table.urls')), 
]
