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
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor, ExtraTreesRegressor, AdaBoostRegressor
from sklearn.linear_model import Lasso, ElasticNet
from xgboost import XGBRegressor
import numpy as np

class DadosBancoAPIView(APIView):
    pagination_class = PageNumberPagination

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

            query = f"SELECT DISTINCT substr(Time, 1, 7) AS year_month FROM {table_name}"
            result = cursor.execute(query).fetchall()

            conn.close()

            available_years_months = [row[0] for row in result]

            return available_years_months

        except Exception as e:
            print(f'Erro ao obter anos e meses disponíveis: {str(e)}')
            return []

    @swagger_auto_schema(
        manual_parameters=[
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
                    'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
                ]
            ),
            openapi.Parameter(
                'year',
                openapi.IN_QUERY,
                description="Ano para filtrar os dados",
                type=openapi.TYPE_INTEGER,
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
            )
        ]
    )
    def get(self, request):
        column_choice = request.query_params.get('column_choice')
        year = request.query_params.get('year')
        month = request.query_params.get('month')
        day = request.query_params.get('day')

        if not column_choice:
            return Response({'error': 'Parâmetro column_choice é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)

        if column_choice not in [
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'
        ]:
            return Response({'error': 'Coluna escolhida inválida'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            table_choice_enum = TableChoice.TOTAL 
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            if year and month and day:
                query = f"SELECT {column_choice} FROM {table_name} WHERE strftime('%Y-%m-%d', Time) = ?"
                query_params = [f"{year}-{month:02}-{day:02}"]
            elif year and month:
                query = f"SELECT {column_choice} FROM {table_name} WHERE strftime('%Y-%m', Time) = ?"
                query_params = [f"{year}-{month:02}"]
            elif year:
                query = f"SELECT {column_choice} FROM {table_name} WHERE strftime('%Y', Time) = ?"
                query_params = [f"{year}"]
            else:
                return Response({'error': 'Pelo menos o parâmetro year deve ser fornecido'}, status=status.HTTP_400_BAD_REQUEST)

            data = cursor.execute(query, query_params).fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=[column_choice])

            return Response({'dados': df.to_dict(orient='records'), 'total_count': len(data)}, status=status.HTTP_200_OK)

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
                enum=['Mapear Feature', 'Baixar Todas as Features Mapeadas', 'Mapear Feature por Feature']
            ),
            openapi.Parameter(
                'feature',
                openapi.IN_QUERY,
                description="Feature a ser mapeada",
                type=openapi.TYPE_STRING,
                enum=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time']
            ),
            openapi.Parameter(
                'feature_to_count',
                openapi.IN_QUERY,
                description="Feature a ser contada com base na primeira feature",
                type=openapi.TYPE_STRING,
                enum=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time']
            )
        ]
    )
    def post(self, request):
        table_choice = request.query_params.get('table_choice')
        action = request.query_params.get('action')
        feature = request.query_params.get('feature')
        feature_to_count = request.query_params.get('feature_to_count')

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
            return self.map_feature(db_path, table_name, feature)
        elif action == 'Baixar Todas as Features Mapeadas':
            return self.download_all_mapped_features(db_path, table_name)
        elif action == 'Mapear Feature por Feature' and feature and feature_to_count:
            return self.map_feature_by_feature(db_path, table_name, feature, feature_to_count)

        return Response({'error': 'Ação inválida ou parâmetros ausentes'}, status=400)

    def map_feature(self, db_path, table_name, feature):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            data = cursor.execute(f"SELECT {feature} FROM {table_name}").fetchall()
            values = [row[0] for row in data]
            return Response({'feature_values': values})
        except Exception as e:
            return Response({'error': f'Erro ao recuperar os valores da feature: {str(e)}'}, status=500)

    def download_all_mapped_features(self, db_path, table_name):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
            df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat', 'Time'])
            mapeamento = {}
            for coluna in df.columns:
                contagem_valores = df[coluna].value_counts().reset_index()
                contagem_valores.columns = [coluna, 'Quantidade']
                sheet_name = coluna[:31]
                mapeamento[coluna] = {'contagem_valores': contagem_valores, 'sheet_name': sheet_name}
            return Response({'mapeamento_features': mapeamento})
        except Exception as e:
            return Response({'error': f'Erro ao baixar todas as features mapeadas: {str(e)}'}, status=500)

    def map_feature_by_feature(self, db_path, table_name, feature, feature_to_count):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            data = cursor.execute(f"SELECT {feature}, {feature_to_count} FROM {table_name}").fetchall()
            df = pd.DataFrame(data, columns=[feature, feature_to_count])
            feature_count = df.groupby(feature)[feature_to_count].apply(list).reset_index()
            feature_count.columns = [feature, f'Valores de {feature_to_count}']
            return Response({'feature_count': feature_count.to_dict(orient='records')})
        except Exception as e:
            return Response({'error': f'Erro ao relacionar os valores das features: {str(e)}'}, status=500)

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
    
class FeatureImportanceAPIView(APIView):
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
                'model_type',
                openapi.IN_QUERY,
                description="Modelos para visualizar os dados de importância",
                type=openapi.TYPE_STRING,
                enum=['GradientBoostingRegressor', 'RandomForestRegressor', 'ExtraTreesRegressor', 'AdaBoostRegressor', 'XGBRegressor', 'ElasticNet']
            )
        ],
        responses={200: 'Model selection data generated successfully'},
    )
    def post(self, request):
        table_choice = request.query_params.get('table_choice')
        model_type = request.query_params.get('model_type')

        if not table_choice or not model_type:
            return Response({'error': 'Parâmetros table_choice e model_type são obrigatórios'}, status=status.HTTP_400_BAD_REQUEST)

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
            selected_data = self.importance_ml(df_filtered, model_type)

            return Response(selected_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def categorize_non_numeric_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for col in df.select_dtypes(include=['object']).columns:
            df[col] = df[col].astype('category').cat.codes
        return df

    def importance_ml(self, df: pd.DataFrame, model_type: str):
        if model_type == 'GradientBoostingRegressor':
            model = GradientBoostingRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = model.feature_importances_
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'RandomForestRegressor':
            model = RandomForestRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = model.feature_importances_
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'ExtraTreesRegressor':
            model = ExtraTreesRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = model.feature_importances_
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'AdaBoostRegressor':
            model = AdaBoostRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = model.feature_importances_
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'XGBRegressor':
            model = XGBRegressor()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = model.feature_importances_
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        elif model_type == 'ElasticNet':
            model = ElasticNet()
            model.fit(df.drop('score_average_Mobat', axis=1), df['score_average_Mobat'])
            feature_importances = np.abs(model.coef_)
            data = {df.columns[i]: feature_importances[i] for i in range(len(feature_importances))}

        else:
            raise ValueError("Model type not supported. Please choose a supported model.")

        return [{'feature': key, 'importance': value} for key, value in data.items()]
    
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
                'table_choice',
                openapi.IN_QUERY,
                description="Escolha o banco de dados",
                type=openapi.TYPE_STRING,
                enum=[choice.name for choice in TableChoice]
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
    def post(self, request, *args, **kwargs):
        table_choice = request.query_params.get('table_choice')
        country = request.query_params.get('country')
        metric = request.query_params.get('metric')

        if not table_choice:
            return Response({'error': 'O parâmetro table_choice é obrigatório'}, status=400)

        if not metric:
            return Response({'error': 'O parâmetro metric é obrigatório'}, status=400)

        try:
            table_choice_enum = TableChoice[table_choice]
            table_name = table_choice_enum.value
            db_path = TableChoice.get_db_path(table_name)
            if not db_path:
                raise KeyError
        except KeyError:
            return Response({'error': 'Opção de tabela inválida'}, status=400)

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
                'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
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
                            return Response({'error': f'País "{country}" não encontrado'}, status=400)
                        
                        filtered_df = df[df['abuseipdb_country_code'] == country_code]
                        if filtered_df.empty:
                            return Response({'error': f'Nenhum dado encontrado para o país {country}'}, status=404)
                        
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
                            return Response({'error': f'País "{country}" não encontrado'}, status=400)
                        
                        filtered_df = df[df['abuseipdb_country_code'] == country_code]
                        if filtered_df.empty:
                            return Response({'error': f'Nenhum dado encontrado para o país {country}'}, status=404)
                        
                        ip_count = filtered_df.shape[0]
                        response_data[country] = ip_count

            else:
                return Response({'error': 'Métrica inválida. Use "average" ou "count"'}, status=400)

            return Response(response_data)

        except Exception as e:
            return Response({'error': str(e)}, status=500)

    # def get(self, request, *args, **kwargs):
    #     return Response({'error': 'Método não suportado'}, status=405)