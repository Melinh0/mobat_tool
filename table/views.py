import sqlite3
from django.db.utils import OperationalError
import pandas as pd
from sklearn.cluster import KMeans
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .filters import TableChoice
from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif, mutual_info_regression, f_regression
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor, ExtraTreesRegressor, AdaBoostRegressor
from sklearn.linear_model import Lasso, ElasticNet, LinearRegression
from xgboost import XGBRegressor
from sklearn.neighbors import KNeighborsRegressor
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import train_test_split
import numpy as np
from io import BytesIO
from django.http import HttpResponse

class DadosBancoAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Erro ao obter anos disponíveis: {str(e)}')
            return []

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'column_choice',
                openapi.IN_QUERY,
                description="Coluna desejada",
                type=openapi.TYPE_STRING,
                enum=[
                    'all', 'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                    'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                    'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                    'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                    'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
                ]
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            ),
            openapi.Parameter(
                'limit',
                openapi.IN_QUERY,
                description="Quantidade de dados a serem retornados",
                type=openapi.TYPE_INTEGER,
                required=False,
                default=None
            ),
            openapi.Parameter(
                'view',
                openapi.IN_QUERY,
                description="Escolha o tipo de visualização: 'excel' para baixar o arquivo ou 'swagger' para visualizar os dados diretamente",
                type=openapi.TYPE_STRING,
                enum=['csv', 'json'],
                default='json'
            )
        ]
    )
    def get(self, request):
        column_choice = request.query_params.get('column_choice')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')
        limit = request.query_params.get('limit')
        view = request.query_params.get('view', 'json')

        if not column_choice:
            return Response({'error': 'Parâmetro column_choice é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        valid_columns = [
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
        ]

        if column_choice != 'all' and column_choice not in valid_columns:
            return Response({'error': 'Coluna escolhida inválida'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query, query_params = self.build_query(column_choice, year, month, day, semester)

            if not query:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            query_params = query_params or []

            if limit is not None:
                query += " LIMIT ?"
                query_params.append(str(int(limit)))

            data = cursor.execute(query, query_params).fetchall()
            columns = [description[0] for description in cursor.description]
            conn.close()

            if view == 'csv':
                df = pd.DataFrame(data, columns=columns)

                csv_buffer = BytesIO()
                df.to_csv(csv_buffer, index=False)
                csv_buffer.seek(0)

                response = HttpResponse(csv_buffer.getvalue(), content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename="dados.csv"'
                return response
            else:
                df = pd.DataFrame(data, columns=columns)
                return Response(df.to_dict(orient='records'))

        except Exception as e:
            print(f'Erro ao obter dados do banco: {str(e)}')
            return Response({'error': f'Erro ao obter dados do banco: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def build_query(self, column_choice, year, month, day, semester):
        query = ""
        query_params = []

        if column_choice == 'all':
            query = f"SELECT * FROM TOTAL"
        else:
            if year and semester:
                if semester == 'Primeiro':
                    query = f"SELECT {column_choice} FROM TOTAL WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query = f"SELECT {column_choice} FROM TOTAL WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return None, None
                query_params = [year]
            elif year and month and day:
                query = f"SELECT {column_choice} FROM TOTAL WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{int(month):02}-{int(day):02}"]
            elif year and month:
                query = f"SELECT {column_choice} FROM TOTAL WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{int(month):02}"]
            elif year:
                query = f"SELECT {column_choice} FROM TOTAL WHERE strftime('%Y', Time) = ?"
                query_params = [year]

        return query, query_params
    
class MapeamentoFeaturesAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Erro ao obter anos disponíveis: {str(e)}')
            return []

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'action',
                openapi.IN_QUERY,
                description="Ação a ser executada",
                type=openapi.TYPE_STRING,
                enum=['Mapear Feature', 'Mapear Feature por Feature'],
                required=True
            ),
            openapi.Parameter(
                'feature_choice',
                openapi.IN_QUERY,
                description="Feature a ser mapeada ou 'all' para todas as features",
                type=openapi.TYPE_STRING,
                enum=[
                    'all', 'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                    'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                    'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                    'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                    'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
                ],
                required=False
            ),
            openapi.Parameter(
                'feature_to_count',
                openapi.IN_QUERY,
                description="Feature a ser contada com base na primeira feature",
                type=openapi.TYPE_STRING,
                enum=[
                    'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                    'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                    'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                    'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                    'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
                ],
                required=False
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            ),
            openapi.Parameter(
                'view_type',
                openapi.IN_QUERY,
                description="Tipo de visualização dos dados ('json' ou 'csv')",
                type=openapi.TYPE_STRING,
                enum=['json', 'csv'],
                required=True
            )
        ]
    )
    def get(self, request):
        action = request.query_params.get('action')
        feature_choice = request.query_params.get('feature_choice')
        feature_to_count = request.query_params.get('feature_to_count')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')
        view_type = request.query_params.get('view_type')

        if not action:
            return Response({'error': 'Parâmetro action é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ?"
            query_params = [year]

            if month:
                query += f" AND strftime('%m', Time) = ?"
                query_params.append(month.zfill(2))

            if day:
                query += f" AND strftime('%d', Time) = ?"
                query_params.append(day.zfill(2))

            if semester:
                if semester == 'Primeiro':
                    query += f" AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query += f" AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return Response({'error': 'Semestre escolhido inválido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            columns = [description[0] for description in cursor.description]
            conn.close()

            df = pd.DataFrame(data, columns=columns)

            if action == 'Mapear Feature':
                if not feature_choice:
                    return Response({'error': 'Parâmetro feature_choice é obrigatório para a ação Mapear Feature'}, status=status.HTTP_400_BAD_REQUEST)
                result_df = self.map_feature(df, feature_choice)

            elif action == 'Mapear Feature por Feature':
                if not feature_choice or not feature_to_count:
                    return Response({'error': 'Parâmetros feature_choice e feature_to_count são obrigatórios para a ação Mapear Feature por Feature'}, status=status.HTTP_400_BAD_REQUEST)
                result_df = self.map_feature_by_feature(df, feature_choice, feature_to_count)

            else:
                result_df = df

            if view_type == 'json':
                return Response(result_df.to_dict(orient='records'))
            elif view_type == 'csv':
                return self.export_to_csv(result_df)
            else:
                return Response({'error': 'Tipo de visualização inválido'}, status=status.HTTP_400_BAD_REQUEST)

        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error': f'Erro ao obter dados do banco: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def map_feature(self, df, feature_choice):
        try:
            if feature_choice == 'all':
                feature_counts = {feature: df[feature].value_counts().reset_index() for feature in df.columns}
                for feature, count_df in feature_counts.items():
                    count_df.columns = [feature, 'count']
                result_df = pd.concat(feature_counts.values(), ignore_index=True)
            elif feature_choice in df.columns:
                feature_values = df[feature_choice].value_counts().reset_index()
                feature_values.columns = [feature_choice, 'count']
                result_df = feature_values
            else:
                raise ValueError('Feature inválida')
            return result_df
        except Exception as e:
            raise ValueError(f'Erro ao mapear feature: {str(e)}')

    def map_feature_by_feature(self, df, feature_choice, feature_to_count):
        try:
            if feature_choice not in df.columns or feature_to_count not in df.columns:
                raise ValueError('Feature escolhida ou feature para contar inválida')

            feature_counts = df.groupby(feature_choice)[feature_to_count].value_counts().unstack(fill_value=0).reset_index()
            feature_counts.columns.name = None
            result_df = feature_counts
            return result_df
        except Exception as e:
            raise ValueError(f'Erro ao mapear feature por feature: {str(e)}')

    def export_to_csv(self, df):
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        response = HttpResponse(csv_buffer.getvalue(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="dados_mapeados.csv"'
        return response
    
class ClusterizacaoAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Erro ao obter anos disponíveis: {str(e)}')
            return []
    
    @staticmethod
    def get_available_columns():
        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"PRAGMA table_info({table_name})"
            cursor.execute(query)
            result = cursor.fetchall()

            conn.close()

            available_columns = [row[1] for row in result if row[1] != 'IP']  
            return available_columns

        except sqlite3.OperationalError as e:
            print(f'Erro ao obter colunas disponíveis: {str(e)}')
            return []

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'feature',
                openapi.IN_QUERY,
                description="Feature para clusterização",
                type=openapi.TYPE_STRING,
                enum=get_available_columns(),
                required=True
            ),
            openapi.Parameter(
                'clusters',
                openapi.IN_QUERY,
                description="Número de clusters desejados",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            ),
            openapi.Parameter(
                'response_format',
                openapi.IN_QUERY,
                description="Formato da resposta (excel ou json)",
                type=openapi.TYPE_STRING,
                enum=['csv', 'json'],
                required=True
            ),
        ],
    )
    def get(self, request):
        feature = request.query_params.get('feature')
        clusters = request.query_params.get('clusters')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')
        response_format = request.query_params.get('response_format')

        if not feature or not clusters or not year or not response_format:
            return Response({'error': 'Parâmetros feature, clusters, year e response_format são obrigatórios'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            num_clusters = int(clusters)
        except ValueError:
            return Response({'error': 'O parâmetro clusters deve ser um número inteiro'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_name = TableChoice.TOTAL.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = ""
            query_params = []

            if year and semester:
                if semester == 'Primeiro':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return Response({'error': 'Semestre escolhido inválido'}, status=status.HTTP_400_BAD_REQUEST)
                query_params = [year]
            elif year and month and day:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ?"
                query_params = [f"{year}"]
            else:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=[
                'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
            ])

            df = self.categorize_non_numeric_columns(df)

            df[feature] = pd.to_numeric(df[feature], errors='coerce')
            df.dropna(subset=[feature], inplace=True)

            X = df[[feature]]
            kmeans = KMeans(n_clusters=num_clusters, random_state=0, n_init=10).fit(X)
            df['cluster'] = kmeans.labels_

            cluster_data = self.get_cluster_data(df, feature)

            if response_format == 'csv':
                return self.export_to_csv(cluster_data)
            elif response_format == 'json':
                return Response(cluster_data)
            else:
                return Response({'error': 'Formato de resposta inválido. Escolha "excel" ou "json"'}, status=status.HTTP_400_BAD_REQUEST)

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
                'data': cluster_data_merged
            })
        return cluster_data

    def categorize_non_numeric_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for col in df.select_dtypes(include=['object']).columns:
            if col != 'IP':
                df[col] = df[col].astype('category').cat.codes
        return df

    def export_to_csv(self, cluster_data):
        csv_buffer = BytesIO()
        all_data = pd.concat([pd.DataFrame(cluster['data']).assign(Cluster=cluster['cluster']) for cluster in cluster_data])
        all_data.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        response = HttpResponse(csv_buffer.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="cluster_data.csv"'
        return response

class FeatureSelectionAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Erro ao obter anos disponíveis: {str(e)}')
            return []
        
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'technique',
                openapi.IN_QUERY,
                description="Seleção de característica para visualizar os dados",
                type=openapi.TYPE_STRING,
                enum=['variance_threshold', 'select_kbest', 'lasso', 'mutual_info', 'correlation']
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            ),
            openapi.Parameter(
                'output_format',
                openapi.IN_QUERY,
                description="Formato de saída desejado (json ou excel)",
                type=openapi.TYPE_STRING,
                enum=['json', 'csv'],
                required=True
            ),
        ],
        responses={200: 'Feature selection data generated successfully'},
    )
    def get(self, request):
        technique = request.query_params.get('technique')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')
        output_format = request.query_params.get('output_format', 'json')

        if not technique:
            return Response({'error': 'Parâmetro technique é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError
        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = ""
            query_params = []

            if year and semester:
                if semester == 'Primeiro':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return Response({'error': 'Semestre escolhido inválido'}, status=status.HTTP_400_BAD_REQUEST)
                query_params = [year]
            elif year and month and day:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ?"
                query_params = [year]
            else:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            columns = [
                'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
            ]
            df = pd.DataFrame(data, columns=columns)
            conn.close()

            allowed_columns = [
                'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
                'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious', 'suspicious',
                'undetected', 'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score',
                'score_average_Mobat'
            ]
            df_filtered = self.categorize_non_numeric_columns(df[allowed_columns])
            selected_data = self.select_features(df_filtered, technique)

            if output_format == 'csv':
                return self.export_to_csv(selected_data)
            else:
                return Response(selected_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def categorize_non_numeric_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = df[col].astype('category').cat.codes
        return df

    def select_features(self, df: pd.DataFrame, technique: str):
        def handle_infinite_values(array):
            array = np.where(np.isinf(array), np.nan, array)
            return np.nan_to_num(array, nan=0.0)
        
        if technique == 'variance_threshold':
            selector = VarianceThreshold()
            selector.fit(df)
            variances = np.array(selector.variances_)
            variances = handle_infinite_values(variances)  
            data = {df.columns[i]: variances[i] for i in range(len(variances))}

        elif technique == 'select_kbest':
            selector = SelectKBest(score_func=f_classif, k=5)
            X = df.drop('score_average_Mobat', axis=1)
            y = df['score_average_Mobat']
            selector.fit(X, y)
            scores = np.array(selector.scores_)
            scores = handle_infinite_values(scores) 
            data = {X.columns[i]: scores[i] for i in range(len(scores))}

        elif technique == 'lasso':
            lasso = Lasso(alpha=0.1)
            X = df.drop('score_average_Mobat', axis=1)
            y = df['score_average_Mobat']
            lasso.fit(X, y)
            coefficients = np.array(lasso.coef_)
            coefficients = handle_infinite_values(coefficients) 
            data = {X.columns[i]: coefficients[i] for i in range(len(coefficients))}

        elif technique == 'mutual_info':
            X = df.drop('score_average_Mobat', axis=1)
            y = df['score_average_Mobat']
            mutual_info = np.array(mutual_info_regression(X, y))
            mutual_info = handle_infinite_values(mutual_info) 
            data = {X.columns[i]: mutual_info[i] for i in range(len(mutual_info))}

        elif technique == 'correlation':
            correlation_matrix = df.corr()
            target_correlations = correlation_matrix['score_average_Mobat']
            correlations = np.array(target_correlations)
            correlations = handle_infinite_values(correlations) 
            data = {target_correlations.index[i]: correlations[i] for i in range(len(correlations))}

        else:
            raise ValueError('Técnica de seleção de características inválida')

        return data

    def export_to_csv(self, data):
        output = BytesIO()
        df = pd.DataFrame(list(data.items()), columns=['Feature', 'Score'])
        df.to_csv(output, index=False, encoding='utf-8', sep=',')
        output.seek(0)         
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=feature_selection.csv'
        return response
    
class FeatureImportanceAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Erro ao obter anos disponíveis: {str(e)}')
            return []

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'model_type',
                openapi.IN_QUERY,
                description="Modelos para visualizar os dados de importância",
                type=openapi.TYPE_STRING,
                enum=['GradientBoostingRegressor', 'RandomForestRegressor', 'ExtraTreesRegressor', 'AdaBoostRegressor', 'XGBRegressor', 'ElasticNet']
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),  
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            ),
            openapi.Parameter(
                'format',
                openapi.IN_QUERY,
                description="Formato da resposta: 'json' ou 'csv'",
                type=openapi.TYPE_STRING,
                enum=['json', 'csv'],
                required=False,
                default='csv'
            )
        ],
        responses={200: 'Model selection data generated successfully'},
    )
    def get(self, request):
        model_type = request.query_params.get('model_type')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')
        response_format = request.query_params.get('format', 'csv')

        if not model_type:
            return Response({'error': 'Parâmetro model_type é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        if model_type not in ['GradientBoostingRegressor', 'RandomForestRegressor', 'ExtraTreesRegressor', 'AdaBoostRegressor', 'XGBRegressor', 'ElasticNet']:
            return Response({'error': 'Model type not supported'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = ""
            query_params = []

            if year and semester:
                if semester == 'Primeiro':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return Response({'error': 'Semestre escolhido inválido'}, status=status.HTTP_400_BAD_REQUEST)
                query_params = [year]
            elif year and month and day:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ?"
                query_params = [year]
            else:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            columns = [description[0] for description in cursor.description]
            conn.close()

            df = pd.DataFrame(data, columns=columns)

            allowed_columns = [
                'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
                'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious', 'suspicious',
                'undetected', 'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score',
                'score_average_Mobat'
            ]
            df_filtered = self.categorize_non_numeric_columns(df[allowed_columns])
            selected_data = self.importance_ml(df_filtered, model_type)

            if response_format == 'csv':
                return self.export_to_csv(selected_data)
            elif response_format == 'json':
                return Response(selected_data, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Formato de resposta inválido'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'error': f'Erro ao obter dados do banco: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def categorize_non_numeric_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = df[col].astype('category').cat.codes
        return df

    def importance_ml(self, df: pd.DataFrame, model_type: str):
        def handle_infinite_values(array):
            array = np.where(np.isinf(array), np.nan, array)
            return np.nan_to_num(array, nan=0.0)
        
        if model_type == 'GradientBoostingRegressor':
            model = GradientBoostingRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = handle_infinite_values(model.feature_importances_)
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'RandomForestRegressor':
            model = RandomForestRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = handle_infinite_values(model.feature_importances_)
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'ExtraTreesRegressor':
            model = ExtraTreesRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = handle_infinite_values(model.feature_importances_)
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'AdaBoostRegressor':
            model = AdaBoostRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = handle_infinite_values(model.feature_importances_)
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'XGBRegressor':
            model = XGBRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = handle_infinite_values(model.feature_importances_)
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'ElasticNet':
            model = ElasticNet()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            coefficients = handle_infinite_values(np.abs(model.coef_))
            data = {df.columns[i]: coefficients[i] for i in range(len(coefficients))}

        else:
            raise ValueError("Model type not supported. Please choose a supported model.")

        return data

    def export_to_csv(self, data):
        output = BytesIO()
        df = pd.DataFrame(list(data.items()), columns=['Feature', 'Importance'])
        df.to_csv(output, index=False, encoding='utf-8', sep=',')
        output.seek(0)         
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=feature_importance.csv'
        return response
    
class CountryScoreAverageView(APIView):
    country_names = {
        'US': 'Estados Unidos', 'CN': 'China', 'SG': 'Singapura', 'DE': 'Alemanha', 'VN': 'Vietnã',
        'KR': 'Coreia do Sul', 'IN': 'Índia', 'RU': 'Rússia', 'LT': 'Lituânia', 'TW': 'Taiwan',
        'GB': 'Reino Unido', 'JP': 'Japão', 'IR': 'Irã', 'BR': 'Brasil', 'AR': 'Argentina',
        'NL': 'Holanda', 'TH': 'Tailândia', 'CA': 'Canadá', 'PK': 'Paquistão', 'ID': 'Indonésia',
        'ET': 'Etiópia', 'FR': 'França', 'BG': 'Bulgária', 'PA': 'Panamá', 'SA': 'Arábia Saudita',
        'BD': 'Bangladesh', 'HK': 'Hong Kong', 'MA': 'Marrocos', 'EG': 'Egito', 'UA': 'Ucrânia',
        'MX': 'México', 'UZ': 'Uzbequistão', 'ES': 'Espanha', 'AU': 'Austrália', 'CO': 'Colômbia',
        'KZ': 'Cazaquistão', 'EC': 'Equador', 'BZ': 'Belize', 'SN': 'Senegal', 'None': 'None',
        'IE': 'Irlanda', 'FI': 'Finlândia', 'ZA': 'África do Sul', 'IT': 'Itália', 'PH': 'Filipinas',
        'CR': 'Costa Rica', 'CH': 'Suíça'
    }
    
    country_codes = {v: k for k, v in country_names.items()}

    def calculate_country_score_average(self, df):
        global_avg_scores = df.groupby('abuseipdb_country_code')['score_average_Mobat'].mean().sort_index()
        return global_avg_scores
    
    def calculate_ip_counts(self, df):
        ip_counts = df['abuseipdb_country_code'].value_counts().sort_index()
        return ip_counts

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=DadosBancoAPIView.get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            ),
            openapi.Parameter(
                'country',
                openapi.IN_QUERY,
                description="Nome do país para visualizar a média do Score Average Mobat ou quantidade de endereços de IP ('Todos' para todos os países)",
                type=openapi.TYPE_STRING,
                enum=['Todos'] + list(country_names.values())
            ),
            openapi.Parameter(
                'metric',
                openapi.IN_QUERY,
                description="Métrica a ser visualizada: 'average' para média do score ou 'count' para contagem de registros de endereços IP",
                type=openapi.TYPE_STRING,
                enum=['average', 'count']
            )
        ],
        responses={200: openapi.Response('Dados gerados com sucesso', schema=openapi.Schema(type=openapi.TYPE_OBJECT))}
    )
    def get(self, request, *args, **kwargs):
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')
        country = request.query_params.get('country')
        metric = request.query_params.get('metric')

        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            if year and semester:
                if semester == 'Primeiro':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return Response({'error': 'Semestre escolhido inválido'}, status=status.HTTP_400_BAD_REQUEST)
                query_params = [year]
            elif year and month and day:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ?"
                query_params = [f"{year}"]
            else:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            conn.close()

            columns = [
                'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
            ]
            df = pd.DataFrame(data, columns=columns)

            response_data = {}

            if metric == 'average':
                if country and country != 'None':
                    if country == 'Todos':
                        country_avg_scores = self.calculate_country_score_average(df)
                        mean_country_avg_score = np.mean(list(country_avg_scores.values))
                        response_data['Média das médias dos países'] = mean_country_avg_score
                        for country_code, country_name in self.country_names.items():
                            response_data[country_name] = country_avg_scores.get(country_code, 0)
                    else:
                        country_code = self.country_codes.get(country)
                        if country_code is None:
                            return Response({'error': f'País "{country}" não encontrado'}, status=status.HTTP_400_BAD_REQUEST)
                        
                        filtered_df = df[df['abuseipdb_country_code'] == country_code]
                        if filtered_df.empty:
                            return Response({'error': f'Nenhum dado encontrado para o país {country}'}, status=status.HTTP_404_NOT_FOUND)
                        
                        country_avg_scores = filtered_df['score_average_Mobat'].mean()
                        response_data[country] = country_avg_scores

                else:
                    global_avg_scores = df['score_average_Mobat'].mean()
                    response_data['Global'] = global_avg_scores

            elif metric == 'count':
                if country and country != 'None':
                    if country == 'Todos':
                        ip_counts = self.calculate_ip_counts(df)
                        mean_ip_count = np.mean(list(ip_counts.values))
                        response_data['Média das quantidades de endereços IP'] = mean_ip_count
                        for country_code, country_name in self.country_names.items():
                            response_data[country_name] = ip_counts.get(country_code, 0)
                    else:
                        country_code = self.country_codes.get(country)
                        if country_code is None:
                            return Response({'error': f'País "{country}" não encontrado'}, status=status.HTTP_400_BAD_REQUEST)
                        
                        filtered_df = df[df['abuseipdb_country_code'] == country_code]
                        if filtered_df.empty:
                            return Response({'error': f'Nenhum dado encontrado para o país {country}'}, status=status.HTTP_404_NOT_FOUND)
                        
                        ip_count = filtered_df.shape[0]
                        response_data[country] = ip_count

                else:
                    total_ip_count = df.shape[0]
                    response_data['Total'] = total_ip_count

            else:
                return Response({'error': 'Métrica inválida. Escolha entre "average" ou "count"'}, status=status.HTTP_400_BAD_REQUEST)

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TopIPsScoreAverageAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Error retrieving available years: {str(e)}')
            return []

    def plot_top_ips_score_average(self, df, num_ips):
        df['score_average_Mobat'] = pd.to_numeric(df['score_average_Mobat'], errors='coerce')
        df = df.dropna(subset=['score_average_Mobat'])

        top_ips = df['IP'].value_counts().nlargest(num_ips).index
        ip_variations = []
        for ip in top_ips:
            ip_data = df[df['IP'] == ip]
            score_variation = ip_data['score_average_Mobat'].max() - ip_data['score_average_Mobat'].min()
            ip_variations.append({
                'IP': ip,
                'ScoreVariation': score_variation,
                'MaxScore': ip_data['score_average_Mobat'].max(),
                'MinScore': ip_data['score_average_Mobat'].min()
            })
        ip_variations_sorted = sorted(ip_variations, key=lambda x: x['ScoreVariation'], reverse=True)

        return ip_variations_sorted

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'num_ips',
                openapi.IN_QUERY,
                description="Number of IPs to analyze",
                type=openapi.TYPE_INTEGER,
                required=True
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Year to filter data",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Month to filter data",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Day to filter data",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semester to filter data ('Primeiro' or 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            )
        ]
    )
    def get(self, request):
        num_ips = int(request.query_params.get('num_ips', 5))  

        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            year = request.query_params.get('year')
            month = request.query_params.get('month')
            day = request.query_params.get('day')
            semester = request.query_params.get('semester')

            query = ""
            query_params = []

            if year and month and day:
                query = f"SELECT IP, score_average_Mobat FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT IP, score_average_Mobat FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                if semester:
                    if semester == 'Primeiro':
                        query = f"SELECT IP, score_average_Mobat FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                    elif semester == 'Segundo':
                        query = f"SELECT IP, score_average_Mobat FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                    else:
                        return Response({'error': ('Invalid semester chosen')}, status=status.HTTP_400_BAD_REQUEST)
                    query_params = [f"{year}"]
                else:
                    query = f"SELECT IP, score_average_Mobat FROM {table_name} WHERE strftime('%Y', Time) = ?"
                    query_params = [f"{year}"]
            else:
                return Response({'error': ('At least the year parameter must be provided')}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            conn.close()

            columns = ['IP', 'score_average_Mobat']
            df = pd.DataFrame(data, columns=columns)

            top_ips_data = self.plot_top_ips_score_average(df, num_ips)

            return Response({'top_ips_data': top_ips_data, 'total_count': len(data)}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': ('Error retrieving data from database: ') + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class DataProcessingAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError("Database path not found")
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Error retrieving available years: {str(e)}')
            return []

    @staticmethod
    def categorize_non_numeric_columns(df):
        non_numeric_columns = df.select_dtypes(exclude=['number']).columns
        for column in non_numeric_columns:
            df[column] = pd.Categorical(df[column]).codes
        return df

    def plot_show_results_table(self, df, columns):
        try:
            print(f"Columns in df: {df.columns}")  
            print(f"Expected columns: {columns}")
            df = self.categorize_non_numeric_columns(df)
            X = df[columns]
            y = df['score_average_Mobat']
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            vt = VarianceThreshold()
            X_train_vt = vt.fit_transform(X_train)
            X_test_vt = vt.transform(X_test)
            
            skb = SelectKBest(score_func=f_regression, k=5)
            X_train_skb = skb.fit_transform(X_train, y_train)
            X_test_skb = skb.transform(X_test)
            
            mrmr_5 = SelectKBest(score_func=mutual_info_regression, k=5)
            X_train_mrmr_5 = mrmr_5.fit_transform(X_train, y_train)
            X_test_mrmr_5 = mrmr_5.transform(X_test)
            
            mrmr_7 = SelectKBest(score_func=mutual_info_regression, k=7)
            X_train_mrmr_7 = mrmr_7.fit_transform(X_train, y_train)
            X_test_mrmr_7 = mrmr_7.transform(X_test)
            
            lasso = Lasso()
            lasso.fit(X_train, y_train)  
            selected_features_lasso = X.columns[lasso.coef_ != 0]
            X_train_lasso = X_train[selected_features_lasso]
            X_test_lasso = X_test[selected_features_lasso]
            
            lr = LinearRegression()
            lr.fit(X_train, y_train)  
            selected_features_lr = X.columns[lr.coef_ != 0]
            X_train_lr = X_train[selected_features_lr]
            X_test_lr = X_test[selected_features_lr]
            
            models = [
                ('GradientBoostingRegressor', GradientBoostingRegressor()),
                ('RandomForestRegressor', RandomForestRegressor()),
                ('ExtraTreesRegressor', ExtraTreesRegressor()),
                ('KNeighborsRegressor', KNeighborsRegressor()),
            ]
            
            results = []
            
            for name, model in models:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                mse = mean_squared_error(y_test, y_pred)
                results.append({'Model': name, 'Selection Technique': 'None', 'MSE': mse})
            
            for name, model in models:
                for X_train_sel, X_test_sel, sel_name in [
                    (X_train_vt, X_test_vt, 'VarianceThreshold'),
                    (X_train_skb, X_test_skb, 'SelectKBest'),
                    (X_train_mrmr_5, X_test_mrmr_5, 'MRMR-5'),
                    (X_train_mrmr_7, X_test_mrmr_7, 'MRMR-7'),
                    (X_train_lasso, X_test_lasso, 'Lasso'),
                    (X_train_lr, X_test_lr, 'LinearRegression')
                ]:
                    model.fit(X_train_sel, y_train)
                    y_pred = model.predict(X_test_sel)
                    mse = mean_squared_error(y_test, y_pred)
                    results.append({'Model': name, 'Selection Technique': sel_name, 'MSE': mse})
            
            results_df = pd.DataFrame(results)
            return results_df.to_dict(orient='records')
        
        except Exception as e:
            print(f'Error processing data: {str(e)}')
            return {'error': 'Error processing data'}

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Year to filter data",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Month to filter data",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Day to filter data",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semester to filter data ('Primeiro' or 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            )
        ]
    )
    def get(self, request):
        try:
            table_choice_enum = TableChoice.TOTAL
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError("Database path not found")

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            year = request.query_params.get('year')
            month = request.query_params.get('month')
            day = request.query_params.get('day')
            semester = request.query_params.get('semester')

            query = ""
            query_params = []

            if year and month and day:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT * FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                if semester:
                    if semester == 'Primeiro':
                        query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                    elif semester == 'Segundo':
                        query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                    else:
                        return Response({'error': ('Invalid semester chosen')}, status=status.HTTP_400_BAD_REQUEST)
                    query_params = [f"{year}"]
                else:
                    query = f"SELECT * FROM {table_name} WHERE strftime('%Y', Time) = ?"
                    query_params = [f"{year}"]
            else:
                return Response({'error': ('At least the year parameter must be provided')}, status=status.HTTP_400_BAD_REQUEST)

            result = cursor.execute(query, query_params).fetchall()

            if not result:
                return Response({'error': ('No data found for the given parameters')}, status=status.HTTP_404_NOT_FOUND)

            conn.close()

            columns = ['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
            ]  

            df = pd.DataFrame(result, columns=columns)

            results = self.plot_show_results_table(df, columns)

            return Response(results, status=status.HTTP_200_OK)

        except Exception as e:
            print(f'Error in API view: {str(e)}')
            return Response({'error': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class DispersaoFeaturesAPIView(APIView):
    @staticmethod
    def get_available_years_months():
        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = f"SELECT DISTINCT strftime('%Y', Time) AS year FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years = [row[0] for row in result]

            return available_years

        except Exception as e:
            print(f'Erro ao obter anos disponíveis: {str(e)}')
            return []

    def categorize_non_numeric_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = df[col].astype('category').cat.codes
        return df

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'feature1',
                openapi.IN_QUERY,
                description="Primeira feature para correlação",
                type=openapi.TYPE_STRING,
                enum=[
                    'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                    'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                    'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                    'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                    'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
                ],
                required=True
            ),
            openapi.Parameter(
                'feature2',
                openapi.IN_QUERY,
                description="Segunda feature para correlação",
                type=openapi.TYPE_STRING,
                enum=[
                    'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
                    'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
                    'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
                    'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
                    'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
                ],
                required=True
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_STRING,
                enum=get_available_years_months(),  
                required=True
            ),
            openapi.Parameter(
                'month',
                openapi.IN_QUERY,
                description="Mês para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'day',
                openapi.IN_QUERY,
                description="Dia para filtrar os dados",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'semester',
                openapi.IN_QUERY,
                description="Semestre para filtrar os dados ('Primeiro' ou 'Segundo')",
                type=openapi.TYPE_STRING,
                enum=['Primeiro', 'Segundo'],
                required=False
            )
        ]
    )
    def get(self, request):
        feature1 = request.query_params.get('feature1')
        feature2 = request.query_params.get('feature2')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')
        semester = request.query_params.get('semester')

        if not feature1 or not feature2:
            return Response({'error': 'Parâmetros feature1 e feature2 são obrigatórios'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            query = ""
            query_params = []

            if year and semester:
                if semester == 'Primeiro':
                    query = f"SELECT {feature1}, {feature2} FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '01' AND '06'"
                elif semester == 'Segundo':
                    query = f"SELECT {feature1}, {feature2} FROM {table_name} WHERE strftime('%Y', Time) = ? AND strftime('%m', Time) BETWEEN '07' AND '12'"
                else:
                    return Response({'error': 'Semestre escolhido inválido'}, status=status.HTTP_400_BAD_REQUEST)
                query_params = [year]
            elif year and month and day:
                query = f"SELECT {feature1}, {feature2} FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT {feature1}, {feature2} FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                query = f"SELECT {feature1}, {feature2} FROM {table_name} WHERE strftime('%Y', Time) = ?"
                query_params = [f"{year}"]
            else:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=[feature1, feature2])
            df = self.categorize_non_numeric_columns(df)

            correlation_matrix = df.corr()
            correlation = correlation_matrix.loc[feature1, feature2]

            correlation_normalized = ((correlation + 1) / 2) * 100

            return Response({'correlation': correlation_normalized}, status=status.HTTP_200_OK)

        except Exception as e:   
            return Response({'error': f'Erro ao obter dados do banco: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
