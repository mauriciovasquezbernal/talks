package main

import (
	"fmt"

	wapc "github.com/wapc/wapc-guest-tinygo"
)

func main() {
	wapc.RegisterFunctions(wapc.Functions{
		"Init":        Init,
		"column_name": column_name,
	})
}

func Init(payload []byte) ([]byte, error) {
	//wapc.ConsoleLog("Hello from Wasm!")
	return nil, nil
}

func column_name(payload []byte) ([]byte, error) {
	var str string
	for i := 0; i < len(payload); i++ {
		length := int(payload[i])
		if length == 0 {
			break
		}
		if i+1+length < len(payload) {
			str += string(payload[i+1:i+1+length]) + "."
		} else {
			wapc.ConsoleLog(fmt.Sprintf("invalid payload %+v\n", payload))
		}
		i += length
	}
	return []byte(str), nil
}
