import pandas as pd
import sqlite3

def csv_to_sqlite(csv_file, db_file, table_name):
    try:
        # Carrega o arquivo CSV para um DataFrame do pandas
        df = pd.read_csv(csv_file)

        # Conecta ao banco de dados SQLite
        conn = sqlite3.connect(db_file)

        # Salva o DataFrame como uma tabela no banco de dados SQLite
        df.to_sql(table_name, conn, if_exists='replace', index=False)

        conn.close()
        print(f"Arquivo CSV '{csv_file}' convertido e salvo como tabela '{table_name}' no banco de dados SQLite '{db_file}' com sucesso.")

    except Exception as e:
        print(f"Erro ao converter CSV para SQLite: {e}")

# Exemplo de uso:
csv_file = '/home/yago/Downloads/ScriptsParaVisualizaçãoDeDados/Ferramenta/Seasons/SegundoSemestre.csv'
db_file = '/home/yago/mobat_tool/table/Seasons/SegundoSemestre.sqlite'
table_name = 'SegundoSemestre'

csv_to_sqlite(csv_file, db_file, table_name)
