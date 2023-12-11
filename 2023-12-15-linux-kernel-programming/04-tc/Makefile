.PHONY: all generate build clean run

BPF_SOURCE=drop.bpf.c
EXECUTABLE=04-tc
BPF_OBJECTS=bpf_bpfeb.go  bpf_bpfeb.o  bpf_bpfel.go  bpf_bpfel.o
GO_SRC=main.go

all: generate build

generate: ${BPF_OBJECTS}

${BPF_OBJECTS}: ${BPF_SOURCE}
	go generate .

build: generate ${EXECUTABLE}

${EXECUTABLE}: ${GO_SRC}
	go build .

run: build
	sudo ./${EXECUTABLE}

clean:
	rm ${EXECUTABLE} ${BPF_OBJECTS}
