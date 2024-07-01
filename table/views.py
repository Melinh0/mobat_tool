import sqlite3
import pandas as pd
from sklearn.cluster import KMeans
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .filters import TableChoice
from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif, mutual_info_regression
from sklearn.linear_model import Lasso
import numpy as np

class DadosBancoAPIView(APIView):
    pagination_class = PageNumberPagination

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'table_choice',
                openapi.IN_QUERY,
                description="Escolha a tabela",
                type=openapi.TYPE_STRING,
                enum=[choice.name for choice in TableChoice]
            ),
            openapi.Parameter(
                'column_choice',
                openapi.IN_QUERY,
                description="Coluna desejada",
                type=openapi.TYPE_STRING,
                enum=[
                    'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                    'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                    'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                    'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                    'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
                ]
            )
        ]
    )
    def get(self, request):
        table_choice = request.query_params.get('table_choice')
        column_choice = request.query_params.get('column_choice')

        if not table_choice:
            return Response({'error': 'Parâmetro table_choice é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        if not column_choice:
            return Response({'error': 'Parâmetro column_choice é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice[table_choice]
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError
            selected_database = table_name
        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=400)

        if column_choice not in [
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ]:
            return Response({'error': 'Coluna escolhida inválida'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            data = cursor.execute(f"SELECT {column_choice} FROM {table_name}").fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=[column_choice])

            return Response({'dados': df.to_dict(orient='records')}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': f'Erro ao obter dados do banco: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MapeamentoFeaturesAPIView(APIView):
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'table_choice',
                openapi.IN_QUERY,
                description="Escolha a tabela",
                type=openapi.TYPE_STRING,
                enum=[choice.name for choice in TableChoice]
            ),
            openapi.Parameter(
                'action',
                openapi.IN_QUERY,
                description="Ação a ser executada",
                type=openapi.TYPE_STRING,
                enum=['Mapear Feature', 'Baixar Todas as Features Mapeadas']
            ),
            openapi.Parameter(
                'feature',
                openapi.IN_QUERY,
                description="Feature a ser mapeada",
                type=openapi.TYPE_STRING,
                enum=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat']
            )
        ]
    )
    def post(self, request):
        table_choice = request.query_params.get('table_choice')
        action = request.query_params.get('action')
        feature = request.query_params.get('feature')

        if not table_choice or not action:
            return Response({'error': 'Parâmetros table_choice e action são obrigatórios'}, status=400)

        try:
            table_choice_enum = TableChoice[table_choice]
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError
            selected_database = table_name
        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=400)

        if action == 'Mapear Feature' and feature:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                data = cursor.execute(f"SELECT {feature} FROM {table_name}").fetchall()
                values = [row[0] for row in data]
                return Response({'feature_values': values})
            except Exception as e:
                return Response({'error': f'Erro ao recuperar os valores da feature: {str(e)}'}, status=500)

        elif action == 'Baixar Todas as Features Mapeadas':
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
                df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'])
                mapeamento = {}
                for coluna in df.columns:
                    contagem_valores = df[coluna].value_counts().reset_index()
                    contagem_valores.columns = [coluna, 'Quantidade']
                    sheet_name = coluna[:31]
                    mapeamento[coluna] = {'contagem_valores': contagem_valores, 'sheet_name': sheet_name}
                return Response({'mapeamento_features': mapeamento})
            except Exception as e:
                return Response({'error': f'Erro ao baixar todas as features mapeadas: {str(e)}'}, status=500)

        return Response({'error': 'Ação inválida ou parâmetros ausentes'}, status=400)

class ClusterizacaoAPIView(APIView):
    pagination_class = PageNumberPagination
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'table_choice',
                openapi.IN_QUERY,
                description="Escolha o banco de dados",
                type=openapi.TYPE_STRING,
                enum=[choice.name for choice in TableChoice]
            ),
            openapi.Parameter(
                'feature',
                openapi.IN_QUERY,
                description="Feature para clusterização",
                type=openapi.TYPE_STRING,
                enum=[
                    'abuseipdb_confidence_score',
                    'abuseipdb_total_reports',
                    'abuseipdb_num_distinct_users',
                    'virustotal_reputation',
                    'harmless',
                    'malicious',
                    'suspicious',
                    'undetected',
                    'IBM_score',
                    'IBM_average_history_Score',
                    'IBM_most_common_score',
                    'score_average_Mobat'
                ]
            ),
            openapi.Parameter(
                'clusters',
                openapi.IN_QUERY,
                description="Número de clusters desejados",
                type=openapi.TYPE_INTEGER
            )
        ],
        responses={200: 'Cluster data generated successfully'},
    )
    def post(self, request):
        table_choice = request.query_params.get('table_choice')
        feature = request.query_params.get('feature')
        clusters = request.query_params.get('clusters')

        if not table_choice or not feature or not clusters:
            return Response({'error': 'Parâmetros table_choice, feature e clusters são obrigatórios'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            num_clusters = int(clusters)
        except ValueError:
            return Response({'error': 'O parâmetro clusters deve ser um número inteiro'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice[table_choice]
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError
        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            data = cursor.fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=[
                'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
            ])

            X = df[[feature]]
            kmeans = KMeans(n_clusters=num_clusters, random_state=0, n_init=10).fit(X)
            df['cluster'] = kmeans.labels_

            cluster_data = self.get_cluster_data(df, feature)
            return Response(cluster_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_cluster_data(self, df, selected_feature):
        cluster_data = []
        for cluster in df['cluster'].unique():
            cluster_df = df[df['cluster'] == cluster]
            cluster_data_counts = cluster_df['IP'].value_counts().reset_index().rename(columns={'index': 'IP', 'IP': 'Quantidade'})
            mean_feature_by_ip = cluster_df.groupby('IP')[selected_feature].mean().reset_index()
            mean_feature_by_ip.rename(columns={selected_feature: f'Mean_{selected_feature}'}, inplace=True)
            cluster_data_merged = pd.merge(cluster_data_counts, mean_feature_by_ip, on='IP', how='left')
            cluster_data.append({
                'cluster': int(cluster),
                'data': cluster_data_merged.to_dict(orient='records')
            })
        return cluster_data
    
class FeatureSelectionAPIView(APIView):
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'table_choice',
                openapi.IN_QUERY,
                description="Escolha o banco de dados",
                type=openapi.TYPE_STRING,
                enum=[choice.name for choice in TableChoice]
            ),
            openapi.Parameter(
                'technique',
                openapi.IN_QUERY,
                description="Seleção de característica para visualizar os dados",
                type=openapi.TYPE_STRING,
                enum=['variance_threshold', 'select_kbest', 'lasso', 'mutual_info', 'correlation']
            )
        ],
        responses={200: 'Feature selection data generated successfully'},
    )
    def post(self, request):
        table_choice = request.query_params.get('table_choice')
        technique = request.query_params.get('technique')

        if not table_choice or not technique:
            return Response({'error': 'Parâmetros table_choice e technique são obrigatórios'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice[table_choice]
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError
        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            data = cursor.fetchall()
            conn.close()

            columns = [
                'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
            ]
            df = pd.DataFrame(data, columns=columns)

            allowed_columns = [
                'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
                'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious', 'suspicious',
                'undetected', 'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score',
                'score_average_Mobat'
            ]
            df_filtered = self.categorize_non_numeric_columns(df[allowed_columns])
            selected_data = self.select_features(df_filtered, technique)

            return Response(selected_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def categorize_non_numeric_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = df[col].astype('category').cat.codes
        return df

    def select_features(self, df: pd.DataFrame, technique: str):
        if technique == 'variance_threshold':
            selector = VarianceThreshold()
            selector.fit(df)
            variances = np.array(selector.variances_).tolist()
            data = {df.columns[i]: variances[i] for i in range(len(variances))}

        elif technique == 'select_kbest':
            selector = SelectKBest(score_func=f_classif, k=5)
            X = df.drop('score_average_Mobat', axis=1)
            y = df['score_average_Mobat']
            selector.fit(X, y)
            scores = np.array(selector.scores_).tolist()
            data = {X.columns[i]: scores[i] for i in range(len(scores))}

        elif technique == 'lasso':
            lasso = Lasso(alpha=0.1)
            X = df.drop('score_average_Mobat', axis=1)
            y = df['score_average_Mobat']
            lasso.fit(X, y)
            coefficients = np.array(lasso.coef_).tolist()
            data = {X.columns[i]: coefficients[i] for i in range(len(coefficients))}

        elif technique == 'mutual_info':
            X = df.drop('score_average_Mobat', axis=1)
            y = df['score_average_Mobat']
            mutual_info = np.array(mutual_info_regression(X, y)).tolist()
            data = {X.columns[i]: mutual_info[i] for i in range(len(mutual_info))}

        elif technique == 'correlation':
            correlation_matrix = df.corr()
            target_correlations = correlation_matrix['score_average_Mobat'].drop('score_average_Mobat')
            data = target_correlations.abs().to_dict()

        else:
            raise ValueError("Invalid technique")

        return [{'feature': key, 'score': value} for key, value in data.items()]
    
