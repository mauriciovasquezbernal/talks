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
import requests

import mysql.connector

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.exporter import jaeger
from opentelemetry.sdk.trace.export import BatchExportSpanProcessor

######################### configure exporters ##################################
# Set preferred tracer implementation
trace.set_tracer_provider(TracerProvider())

# configure exporter to Jaeger
jaeger_exporter = jaeger.JaegerSpanExporter(
    service_name="my-server",
    agent_host_name="localhost",
    agent_port=6831,
)

trace.get_tracer_provider().add_span_processor(
    BatchExportSpanProcessor(jaeger_exporter)
)

############################# application code #################################
app = flask.Flask(__name__)

mydb = mysql.connector.connect(
  user=MYSQL_USER,
  password=MYSQL_PASSWORD,
  host=MYSQL_HOST,
  port=MYSQL_PORT,
  database=MYSQL_DB_NAME,
)

mycursor = mydb.cursor()
sql = "SELECT * FROM continents WHERE name ='{}'"

@app.route("/")
def get_continent():
    country = flask.request.args.get("country")
    mycursor.execute(sql.format(country))
    sqlresult = mycursor.fetchall()

    return sqlresult[0][1]

if __name__ == "__main__":
    app.run(debug=True)
