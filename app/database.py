import mysql.connector
from mysql.connector import Error
import sqlite3

def get_db_connection():
    try:
        conn = sqlite3.connect('test_database.db') 
        return conn
    except Error as e:
        print(f"Error: {e}")
        raise