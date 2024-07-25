import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # Lista para armazenar DataFrames temporários
    dfs = []
    
    # Verificar se o JSON tem a chave 'feature_values' e se seu valor é um dicionário
    if 'feature_values' in data and isinstance(data['feature_values'], dict):
        # Iterar sobre as chaves no dicionário 'feature_values'
        for key, value in data['feature_values'].items():
            # Verificar se o valor é um dicionário
            if isinstance(value, dict):
                # Criar um DataFrame a partir do dicionário
                df = pd.DataFrame(list(value.items()), columns=[key, 'Count'])
                # Adicionar uma coluna para identificar o tipo de dado
                df['Type'] = key
                # Adicionar o DataFrame à lista
                dfs.append(df)
            else:
                raise ValueError(f"O valor da chave '{key}' não é um dicionário.")
    else:
        raise ValueError("O JSON não está no formato esperado.")
    
    # Concatenar todos os DataFrames na lista em um único DataFrame
    result_df = pd.concat(dfs, ignore_index=True)
    
    # Salvar o DataFrame resultante em um arquivo CSV
    result_df.to_csv(csv_file, index=False)

# Nome do arquivo
json_file = '/home/yago/Downloads/response_1721930087345.json'  # Nome do arquivo JSON de entrada
csv_file = 'mapping.csv'  # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
