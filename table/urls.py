from django.urls import path
from . import views 

urlpatterns = [
    path('mapeamento-features/', views.MapeamentoFeaturesAPIView.as_view(), name='mapeamento-features'),
    path('api/clusterizacao/', views.ClusterizacaoAPIView.as_view(), name='clusterizacao'),
    path('feature-selection/', views.FeatureSelectionAPIView.as_view(), name='feature-selection'),
    path('dados-banco/', views.DadosBancoAPIView.as_view(), name='dados_banco'),
    path('feature_importance/', views.FeatureImportanceAPIView.as_view(), name='feature_importance'),
    path('country-score-average/', views.CountryScoreAverageView.as_view(), name='country-score-average'),
    path('top-ips-score-average/', views.TopIPsScoreAverageAPIView.as_view(), name='top-ips-score-average'),
    path('data-processing/', views.DataProcessingAPIView.as_view(), name='data-processing'),  
    path('dispersao-features/', views.DispersaoFeaturesAPIView.as_view(), name='dispersao-features'),  

]
