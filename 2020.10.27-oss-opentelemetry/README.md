# Enabling Observability with OpenTelemetry

Slides are available [here](https://docs.google.com/presentation/d/1gRTZLVq5z0_uoZZ_egI37ttax5r_AEFEHvmMs4fMAWc)

## Demo

This demo was carried on with Python `3.7.4`.

Start the required services with docker-compose

```
$ docker-compose up
```

Install the dependencies

```
$ pip install -r requirements.txt
```

### Creata DB table

```
$ python create_table.py
```

### Instrumented case

Start the server

```
$ cd instrumented
$ python server.py
```

Perform some requests using the client

```
$ cd instrumented
$ python client.py Colombia
$ python client.py Italy
$ python client.py Australia
```

Check the traces in Jaeger http://localhost:16686/.

### Automatic Instrumentation

Start the server

```
$ cd uninstrumented
$ opentelemetry-instrument python server.py
```

Perform some requests using the client

```
$ cd uninstrumented
$ opentelemetry-instrument python client.py Colombia
$ opentelemetry-instrument python client.py Italy
$ opentelemetry-instrument python client.py Australia
```

Check the traces in Jaeger http://localhost:16686/.
