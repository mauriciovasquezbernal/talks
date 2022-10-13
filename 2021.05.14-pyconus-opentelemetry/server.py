#!/usr/bin/env python3
#
# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


MYSQL_USER = "testuser"
MYSQL_PASSWORD = "testpassword"
MYSQL_HOST = "localhost"
MYSQL_PORT = 3306
MYSQL_DB_NAME = "opentelemetry-tests"

import os

import flask
import mysql.connector
import requests

mydb = mysql.connector.connect(
  user=MYSQL_USER,
  password=MYSQL_PASSWORD,
  host=MYSQL_HOST,
  port=MYSQL_PORT,
  database=MYSQL_DB_NAME,
)

mycursor = mydb.cursor()
sql = "SELECT * FROM continents WHERE name ='{}'"

app = flask.Flask(__name__)

@app.route("/")
def get_continent():
    country = flask.request.args.get("country")
    mycursor.execute(sql.format(country))
    sqlresult = mycursor.fetchall()

    return sqlresult[0][1]

if __name__ == "__main__":
    #app.run(debug=True, use_reloader=False, port=5000)
    app.run(debug=True, port=5000)
