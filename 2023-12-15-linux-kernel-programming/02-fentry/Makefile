.PHONY: all generate build clean run

all: generate build

generate:
	go generate .

build:
	go build .

run:
	sudo ./02-fentry

clean:
	rm 02-fentry
	rm bpf_*
