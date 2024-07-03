import sqlite3
import csv

def csv_to_sqlite(csv_file, db_file, table_name):
    conn = None

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)
            columns = ','.join(f'"{header}"' for header in headers)  # Envolve os nomes de colunas com aspas duplas
            placeholders = ','.join(['?'] * len(headers))
            create_table_query = f"CREATE TABLE IF NOT EXISTS {table_name} ({columns});"
            cursor.execute(create_table_query)

            insert_query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders});"
            for row in reader:
                cursor.execute(insert_query, row)

        conn.commit()
        print(f"Arquivo CSV '{csv_file}' convertido para SQLite '{db_file}' na tabela '{table_name}' com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados SQLite: {e}")

    finally:
        if conn:
            conn.close()

# Exemplo de uso:
csv_file = '/home/yago/Downloads/Total.csv'   # Substitua pelo caminho do seu arquivo CSV
db_file = '/home/yago/mobat_tool/mobat_tool/Seasons/Total.sqlite'       # Substitua pelo caminho onde deseja salvar o arquivo SQLite
table_name = 'Total'                # Nome da tabela que será criada no SQLite

csv_to_sqlite(csv_file, db_file, table_name)
