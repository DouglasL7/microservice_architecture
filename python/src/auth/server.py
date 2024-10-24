import jwt, datetime, os
import mysql.connector
from flask import Flask, request


server = Flask(__name__)

db_config = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "user": os.getenv("MYSQL_USER", "auth_user@localhost"),
    "password": os.getenv("MYSQL_PASSWORD", "Admin123"),
    "database": os.getenv("MYSQL_DB", "auth"),
}


def get_db_connection():
    return mysql.connector.connect(**db_config)


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "Missing credentials", 401

    # check db for username and password
    connection = get_db_connection()
    cursor = connection.cursor()

    res = cursor.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username)
    )

    if res > 0:
        user_row = cursor.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "Invalid credentials", 401
        else:
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)

    else:
        return "Invalid credentials", 401
