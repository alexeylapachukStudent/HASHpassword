import mysql.connector
from mysql.connector import Error


def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="test_user",
            password="testuser20",
            database="user_pass"
        )
        
        if conn.is_connected():
            return conn 
    except Error as e:
        print(f"Erorr: {e}")
        raise 