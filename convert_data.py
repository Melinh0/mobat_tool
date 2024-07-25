import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # Verificar se o JSON tem a chave 'feature_values' e se seu valor é uma lista
    if 'feature_values' in data and isinstance(data['feature_values'], list):
        # Criar um DataFrame a partir da lista de dicionários
        df = pd.DataFrame(data['feature_values'])
        
        # Salvar o DataFrame em um arquivo CSV
        df.to_csv(csv_file, index=False)
    else:
        raise ValueError("O JSON não está no formato esperado.")

# Nome do arquivo
json_file = '/home/yago/Downloads/response_1721930087345.json'  # Nome do arquivo JSON de entrada
csv_file = 'mapping.csv'  # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
