# Distributed Tracing with OpenTelemetry

Slides are available [here](https://docs.google.com/presentation/d/1SLY0DEU1RToIdmxdpCn5PsOuggyuHlZkojOHPZJyDNw/edit?usp=sharing)

## Demo

This demo was tried with Python `3.7.4`.

Start the required services with docker-compose

```
$ docker-compose up
```

Install the dependencies

```
$ pip install -r requirements.txt
```

## Initiate DB

```
$ mysql --user=testuser --password=testpassword --host=localhost --protocol=TCP opentelemetry-test

> CREATE TABLE continents (name VARCHAR(30) PRIMARY KEY, continent VARCHAR(30));
> INSERT INTO continents(name, continent) VALUES("Italy", "Europe");
> INSERT INTO continents(name, continent) VALUES("Colombia", "America");
> INSERT INTO continents(name, continent) VALUES("China", "Asia");
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
$ python client_instrumented.py China
```

Check the traces in Jaeger http://localhost:16686/.

### Automatic Instrumentation

Start the server

```
$ opentelemetry-instrument --trace-exporter=jaeger_thrift python server.py
```

Perform some requests using the client

```
$ opentelemetry-instrument --trace-exporter=jaeger_thrift python client.py Colombia
$ opentelemetry-instrument --trace-exporter=jaeger_thrift python client.py Italy
$ opentelemetry-instrument --trace-exporter=jaeger_thrift python client.py China
```

Check the traces in Jaeger http://localhost:16686/.
