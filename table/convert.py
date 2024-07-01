import sqlite3

def convert_column_to_float(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Verifica se a coluna existe na tabela
        cursor.execute("PRAGMA table_info('SegundoSemestre')")
        columns = [column[1] for column in cursor.fetchall()]
        if 'score_average_Mobat' not in columns:
            raise ValueError("Coluna 'score_average_Mobat' não encontrada na tabela.")

        # Converte a coluna para float
        cursor.execute("UPDATE SegundoSemestre SET score_average_Mobat = CAST(score_average_Mobat AS REAL)")

        conn.commit()
        conn.close()
        print("Coluna 'score_average_Mobat' convertida para tipo float com sucesso.")

    except sqlite3.Error as e:
        print(f"Erro ao conectar ao banco de dados SQLite: {e}")

# Exemplo de uso:
db_path = '/home/yago/mobat_tool/table/Seasons/SegundoSemestre.sqlite'
convert_column_to_float(db_path)
