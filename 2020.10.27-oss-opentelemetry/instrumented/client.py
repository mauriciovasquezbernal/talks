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

import os
import sys

import requests

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

# Import package for exporter
from opentelemetry.exporter import jaeger
from opentelemetry.sdk.trace.export import BatchExportSpanProcessor

# Import requests instrumentation library
from opentelemetry.instrumentation.requests import RequestsInstrumentor

############################### framework setup ################################
# Set preferred tracer implementation must be set
trace.set_tracer_provider(TracerProvider())

# Configure exporter to Jaeger
jaeger_exporter = jaeger.JaegerSpanExporter(
    service_name="my-client",
    agent_host_name="localhost",
    agent_port=6831,
)

trace.get_tracer_provider().add_span_processor(
    BatchExportSpanProcessor(jaeger_exporter)
)

# Enable instrumentation in the requests library.
RequestsInstrumentor().instrument()

tracer = trace.get_tracer(__name__)

############################# application code #################################
country=sys.argv[1]
payload={"country": country}

with tracer.start_as_current_span("query_http_service"):
    response = requests.get(url="http://127.0.0.1:5000/", params=payload)
print(response.text)
