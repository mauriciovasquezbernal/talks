.PHONY: all generate build clean run

BPF_SOURCE=fentry.bpf.c
EXECUTABLE=02-fentry
BPF_OBJECTS=bpf_bpfel_x86.go bpf_bpfel_x86.o
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
