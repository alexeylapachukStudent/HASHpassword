import mysql.connector
from mysql.connector import Error


def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="alexlapachuk",
            password="alex18",
            database="auth_system"
        )
        
        if conn.is_connected():
            return conn 
    except Error as e:
        print(f"Erorr: {e}")
        raise 