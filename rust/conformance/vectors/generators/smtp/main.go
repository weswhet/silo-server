// Command smtp records what the real net/textproto DotWriter, which go-mail writes a message body
// through, puts on the wire. rust/crates/silo-runtime/tests/smtp.rs replays it against dot_stuff.
//
// Commands assume the repository root is the cwd:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/vectors/generators/smtp
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"net/textproto"
	"os"
)

type record struct {
	Input string `json:"input_hex"`
	Wire  string `json:"wire_hex"`
}

func dotWrite(input []byte, chunk int) []byte {
	var out bytes.Buffer
	buffered := bufio.NewWriter(&out)
	w := textproto.NewWriter(buffered).DotWriter()
	for len(input) > 0 {
		n := min(chunk, len(input))
		if _, err := w.Write(input[:n]); err != nil {
			log.Fatal(err)
		}
		input = input[n:]
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	return out.Bytes()
}

func main() {
	inputs := [][]byte{
		{}, []byte("."), []byte(".\r\n"), []byte("a"), []byte("a\n"), []byte("a\r\n"), []byte("a\r"), []byte("\r"), []byte("\n"), []byte("\r\n"),
		[]byte("a\r\n.\r\nMAIL FROM:<evil@example.com>\r\n"), []byte("a\n.\nb"), []byte("..\r\n..."), []byte("a\r.b"), []byte("a\r\r\n.b"), []byte("a\n\n.\n"), []byte("\xff.\xfe\r\n.\xff"),
	}
	r := rand.New(rand.NewSource(20261101))
	alphabet := []byte("\r\n.ab")
	for i := 0; i < 3000; i++ {
		input := make([]byte, r.Intn(16))
		for j := range input {
			input[j] = alphabet[r.Intn(len(alphabet))]
		}
		inputs = append(inputs, input)
	}
	var records []record
	for _, input := range inputs {
		wire := dotWrite(input, 1+len(input))
		if !bytes.Equal(wire, dotWrite(input, 1)) {
			log.Fatalf("chunking changed the output for %q", input)
		}
		records = append(records, record{Input: hex.EncodeToString(input), Wire: hex.EncodeToString(wire)})
	}
	data, err := json.Marshal(records)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("rust/conformance/vectors/smtp/dot_writer.json", append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d cases", len(records))
}
