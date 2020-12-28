package mtproto

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/internal/testutil"
	"github.com/gotd/td/mtproto/internal/rpc"
)

func TestClientHandleMessage(t *testing.T) {
	c := &Client{
		rand: Zero{},
		log:  zap.NewNop(),
	}

	for i, input := range []string{
		"\xdc\xf8\xf1stewa\x00O\x03expired c" +
			"ertificate\x02\x00\x00\x00\xef",

		"\x01m\\\xf300000000\x19\xcaD!0000" +
			"\x1100000000000000000",

		"\x01m\\\xf300000000\x19\xcaD!0000" +
			"\xfe0",

		"@B\xaet\x15ĵ\x1c0000,\x8f\xf8B0000" +
			"00000000\x15ĵ\x1c0000\xff000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"00000000000000000000" +
			"000000000000",
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			if err := c.handleMessage(&bin.Buffer{Buf: []byte(input)}); err == nil {
				t.Fatal("error expected")
			}
		})
	}
}

func TestClientHandleMessageCorpus(t *testing.T) {
	c := &Client{
		rand:           Zero{},
		log:            zap.NewNop(),
		sessionCreated: createCondOnce(),
		rpc:            rpc.New(rpc.NopSend, rpc.Config{}),
	}
	c.sessionCreated.Done()

	corpus, err := ioutil.ReadDir(filepath.Join("..", "_fuzz", "handle_message", "corpus"))
	if os.IsNotExist(err) {
		t.Skip("No corpus")
	}
	for _, f := range corpus {
		data, err := ioutil.ReadFile(filepath.Join("..", "_fuzz", "handle_message", "corpus", f.Name()))
		if err != nil {
			t.Fatal(err)
		}

		// TODO(ernado): Investigate big allocations and reduce threshold
		const allocThreshold = 512

		testutil.MaxAlloc(t, allocThreshold, func() {
			_ = c.handleMessage(&bin.Buffer{Buf: data})
		})
	}
}
