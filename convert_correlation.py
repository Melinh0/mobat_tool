import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # Preparar os dados para o DataFrame
    # Se data for uma lista de dicionários
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        # Extrair o primeiro dicionário da lista
        data_dict = data[0]
        # Converter o JSON em uma lista de dicionários
        data_list = [{'Key': key, 'Value': value} for key, value in data_dict.items()]
    else:
        raise ValueError("O JSON não está no formato esperado.")
    
    # Criar um DataFrame com os dados
    df = pd.DataFrame(data_list)
    
    # Salvar o DataFrame em um arquivo CSV
    df.to_csv(csv_file, index=False)

# Nome dos arquivos
json_file = '/home/yago/Downloads/response_1721926992318.json'  # Nome do arquivo JSON de entrada
csv_file = 'correlation.csv'    # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
