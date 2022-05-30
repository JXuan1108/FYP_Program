import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Ap411738Cd./"
)

my_cursor = mydb.cursor()

my_cursor.execute("CREATE DATABASE users")
