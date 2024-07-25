import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # Preparar os dados para o DataFrame
    # Converter o JSON em uma lista de dicionários
    data_list = [{'País': key, 'Média': value} for key, value in data.items()]
    
    # Criar um DataFrame com os dados
    df = pd.DataFrame(data_list)
    
    # Salvar o DataFrame em um arquivo CSV
    df.to_csv(csv_file, index=False)

# Nome dos arquivos
json_file = '/home/yago/Downloads/response_1721926532187.json'  # Nome do arquivo JSON de entrada
csv_file = 'dados_paises.csv'    # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
