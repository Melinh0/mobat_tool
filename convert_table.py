import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # Verificar se o JSON tem a chave 'top_ips_data' e se seu valor é uma lista de dicionários
    if 'top_ips_data' in data and isinstance(data['top_ips_data'], list):
        # Criar um DataFrame diretamente da lista de dicionários
        df = pd.DataFrame(data['top_ips_data'])
    else:
        raise ValueError("O JSON não está no formato esperado.")
    
    # Salvar o DataFrame em um arquivo CSV
    df.to_csv(csv_file, index=False)

# Nome dos arquivos
json_file = '/home/yago/Downloads/response_1721927042622.json'  # Nome do arquivo JSON de entrada
csv_file = 'table.csv'    # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
