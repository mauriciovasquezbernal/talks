.PHONY: all generate build clean run

all: generate build

generate:
	go generate .

build:
	go build .

run:
	sudo ./01-kprobes

clean:
	rm 01-kprobes
	rm bpf_*
