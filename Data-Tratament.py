import pandas as pd
from sklearn.cluster import KMeans
from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif
from sklearn.linear_model import Lasso
from sklearn.feature_selection import mutual_info_regression
import numpy as np

def process_csv(input_csv, feature_output_prefix, cluster_output, feature_selection_techniques, feature_selection_output_prefix):
    try:
        # Ler o arquivo CSV
        df = pd.read_csv(input_csv)

        # Parte 1: Mapeamento de Features
        features = df.columns
        for feature in features:
            feature_df = df[[feature]]
            feature_df.to_csv(f'{feature_output_prefix}_{feature}.csv', index=False)
        print("Mapeamento de features concluído. Arquivos CSV gerados.")

        # Parte 2: Clusterização
        numeric_features = df.select_dtypes(include='number').columns
        kmeans = KMeans(n_clusters=3, random_state=42)
        df['cluster'] = kmeans.fit_predict(df[numeric_features])
        cluster_summary = df.groupby('cluster').agg(
            IP_count=('IP', 'count'),
            mean_features=df[numeric_features].mean()
        ).reset_index()
        cluster_summary.to_csv(cluster_output, index=False)
        print("Clusterização concluída. Arquivo CSV gerado.")

        # Parte 3: Seleção de Características
        X = df.drop('score_average_Mobat', axis=1)
        y = df['score_average_Mobat']

        for technique in feature_selection_techniques:
            if technique == 'variance_threshold':
                selector = VarianceThreshold()
                selector.fit(X)
                variances = np.array(selector.variances_).tolist()
                data = {X.columns[i]: variances[i] for i in range(len(variances))}
                feature_scores = [{'feature': key, 'score': value} for key, value in data.items()]
                output_file = f'{feature_selection_output_prefix}_variance_threshold.csv'

            elif technique == 'select_kbest':
                selector = SelectKBest(score_func=f_classif, k=5)
                selector.fit(X, y)
                scores = np.array(selector.scores_).tolist()
                data = {X.columns[i]: scores[i] for i in range(len(scores))}
                feature_scores = [{'feature': key, 'score': value} for key, value in data.items()]
                output_file = f'{feature_selection_output_prefix}_select_kbest.csv'

            elif technique == 'lasso':
                lasso = Lasso(alpha=0.1)
                lasso.fit(X, y)
                coefficients = np.array(lasso.coef_).tolist()
                data = {X.columns[i]: coefficients[i] for i in range(len(coefficients))}
                feature_scores = [{'feature': key, 'score': value} for key, value in data.items()]
                output_file = f'{feature_selection_output_prefix}_lasso.csv'

            elif technique == 'mutual_info':
                mutual_info = np.array(mutual_info_regression(X, y)).tolist()
                data = {X.columns[i]: mutual_info[i] for i in range(len(mutual_info))}
                feature_scores = [{'feature': key, 'score': value} for key, value in data.items()]
                output_file = f'{feature_selection_output_prefix}_mutual_info.csv'

            elif technique == 'correlation':
                correlation_matrix = X.corrwith(y)
                data = correlation_matrix.abs().to_dict()
                feature_scores = [{'feature': key, 'score': value} for key, value in data.items()]
                output_file = f'{feature_selection_output_prefix}_correlation.csv'

            else:
                print(f"Técnica de seleção de características inválida: {technique}")
                continue

            # Salvar o arquivo CSV para a técnica atual
            pd.DataFrame(feature_scores).to_csv(output_file, index=False)
            print(f"Seleção de características usando {technique} concluída. Arquivo CSV gerado: {output_file}")

    except Exception as e:
        print(f'Erro ao processar o arquivo CSV: {str(e)}')

# Exemplo de uso
process_csv(
    input_csv='filtered_data.csv',
    feature_output_prefix='mapped_features',
    cluster_output='cluster_data.csv',
    feature_selection_techniques=['variance_threshold', 'select_kbest', 'lasso', 'mutual_info', 'correlation'],
    feature_selection_output_prefix='feature_selection'
)
