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


import mysql.connector

mydb = mysql.connector.connect(
  user=MYSQL_USER,
  password=MYSQL_PASSWORD,
  host=MYSQL_HOST,
  port=MYSQL_PORT,
  database=MYSQL_DB_NAME,
)

mycursor = mydb.cursor()
mycursor.execute('drop table continents')
mycursor.execute('create table continents (name VARCHAR(255) PRIMARY KEY, continent VARCHAR(255))')
mycursor.execute('insert into continents (name, continent) values ("Colombia", "America")')
mycursor.execute('insert into continents (name, continent) values ("Italy", "Europe")')
mycursor.execute('insert into continents (name, continent) values ("Australia", "Oceania")')

mydb.commit()
