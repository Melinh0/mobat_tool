from django.urls import path
from . import views 

urlpatterns = [
    path('mapeamento-features/', views.MapeamentoFeaturesAPIView.as_view(), name='mapeamento-features'),
    path('clusterizacao/', views.ClusterizacaoAPIView.as_view(), name='clusterizacao_api'),
    path('feature-selection/', views.FeatureSelectionAPIView.as_view(), name='feature-selection'),
    path('dados-banco/', views.DadosBancoAPIView.as_view(), name='dados_banco'),

]
