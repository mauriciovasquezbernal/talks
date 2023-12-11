.PHONY: all generate build clean run

all: generate build

generate:
	go generate .

build:
	go build .

run:
	sudo ./03-tracepoint

clean:
	rm 03-tracepoint
	rm bpf_*
