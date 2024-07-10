import sqlite3

def visualizar_dados_sqlite(db_file):
    try:
        # Conectar ao banco de dados SQLite
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Exemplo de consulta: selecionar todos os dados da tabela 'TOTAL'
        cursor.execute("SELECT * FROM TOTAL")

        # Obter os nomes das colunas
        col_names = [description[0] for description in cursor.description]

        # Recuperar todos os dados
        rows = cursor.fetchall()

        # Exibir os dados retornados
        for row in rows:
            print(row)

        print("Colunas presentes na tabela 'TOTAL':", col_names)

        # Fechar a conexão com o banco de dados
        conn.close()

    except sqlite3.Error as e:
        print(f"Erro ao acessar o banco de dados SQLite: {e}")

# Substitua '/home/yago/mobat_tool/mobat_tool/Seasons/Total.sqlite' pelo caminho do seu arquivo SQLite
visualizar_dados_sqlite('/home/yago/mobat_tool/mobat_tool/Seasons/Total.sqlite')
