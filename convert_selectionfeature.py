import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # Verificar se o JSON é uma lista de dicionários
    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
        # Criar um DataFrame diretamente a partir da lista de dicionários
        df = pd.DataFrame(data)
    else:
        raise ValueError("O JSON não está no formato esperado.")
    
    # Salvar o DataFrame em um arquivo CSV
    df.to_csv(csv_file, index=False)

# Nome dos arquivos
json_file = '/home/yago/Downloads/response_1721927014361.json'  # Nome do arquivo JSON de entrada
csv_file = 'features_importance.csv'    # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
