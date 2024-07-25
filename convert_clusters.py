import pandas as pd
import json

# Função para converter JSON em CSV
def json_to_csv(json_file, csv_file):
    # Abrir e carregar o arquivo JSON
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    # List to hold all data
    all_data = []
    
    # Iterar sobre cada cluster no JSON
    for cluster in data:
        # Adicionar cada item de 'data' à lista com a informação do cluster
        for item in cluster['data']:
            item['cluster'] = cluster['cluster']
            all_data.append(item)
    
    # Criar um DataFrame com os dados
    df = pd.DataFrame(all_data)
    
    # Salvar o DataFrame em um arquivo CSV
    df.to_csv(csv_file, index=False)

# Nome dos arquivos
json_file = '/home/yago/Downloads/response_1721926506607.json'  # Nome do arquivo JSON de entrada
csv_file = 'clusters.csv'    # Nome do arquivo CSV de saída

# Converter JSON para CSV
json_to_csv(json_file, csv_file)
