# Distributed Tracing with OpenTelemetry

Slides are available [here](https://docs.google.com/presentation/d/169kxDHyyRGzclnJwCMkWakfvQNOGIgNZx2mGJ6nQHds/edit?usp=sharing)

## Demo

This demo was tried with Python `3.7.4`.

Start the required services with docker-compose

```
$ cd 001-devopsdaysbogota2020-opentelemetry
$ docker-compose up
```

Install the dependencies

```
$ pip install -r requirements.txt
```

### Instrumented case

Start the server

```
$ python server_instrumented.py
```

Perform some requests using the client

```
$ python client_instrumented.py Colombia
$ python client_instrumented.py Italy
$ python client_instrumented.py Germany
```

Check the traces in Jaeger http://localhost:16686/.

### Automatic Instrumentation

Start the server

```
$ opentelemetry-instrument python serverserver.py
```

Perform some requests using the client

```
$ opentelemetry-instrument python client.py Colombia
$ opentelemetry-instrument python client.py Italy
$ opentelemetry-instrument python client.py Germany
```

Check the traces in Jaeger http://localhost:16686/.
