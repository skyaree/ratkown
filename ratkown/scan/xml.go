package scan

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
)

const (
	XOR_CONST = 0x33941615D
	XOR_MASK  = 0xFFFFFFFF
	SEED0     = 0xDEADBEEF
)

func nextSeed(seed uint32) uint32 {
	return uint32((uint64(seed) + XOR_CONST) & XOR_MASK)
}

func applyCore(buf []byte, seed0 uint32) {
	seed := nextSeed(seed0)
	n := len(buf)

	i := 0
	for i < n-3 {
		word := binary.LittleEndian.Uint32(buf[i : i+4])
		word ^= seed
		binary.LittleEndian.PutUint32(buf[i:i+4], word)
		i++
		seed = nextSeed(seed)
	}

	tailIndex := n - 3
	var seedBytes [4]byte
	for tailIndex < n {
		binary.LittleEndian.PutUint32(seedBytes[:], seed)
		for j := 0; j < 4; j++ {
			rawPos := tailIndex + j
			pos := rawPos
			if rawPos >= n {
				pos = rawPos % n
			}
			buf[pos] ^= seedBytes[j]
		}
		tailIndex++
		seed = nextSeed(seed)
	}
}

func FastEnc(password string) string {
	tail := []byte("p2pwn")
	extra := []byte("p2pwnnownsdahuacams")
	seed0 := uint32(SEED0)

	decoded := []byte(password)
	decoded = append(decoded, tail...)

	tailLenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(tailLenBuf, uint32(len(tail)))
	decoded = append(decoded, tailLenBuf...)

	decoded = append(decoded, extra...)

	extraLenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(extraLenBuf, uint32(len(extra)))
	decoded = append(decoded, extraLenBuf...)

	applyCore(decoded, seed0)

	seed0Buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(seed0Buf, seed0)
	decoded = append(decoded, seed0Buf...)

	return base64.StdEncoding.EncodeToString(decoded)
}

func EscapeXML(s string) string {
	var buf strings.Builder
	for _, c := range s {
		switch c {
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '&':
			buf.WriteString("&amp;")
		case '"':
			buf.WriteString("&quot;")
		case '\'':
			buf.WriteString("&apos;")
		default:
			buf.WriteRune(c)
		}
	}
	return buf.String()
}

func BuildDeviceXMLRow(serial string, login string, encryptedPassword string) string {
	s := EscapeXML(serial)
	l := EscapeXML(login)
	b := EscapeXML(encryptedPassword)
	return "\t" + `<Device name="` + s + `" domain="` + s + `" port="37777" username="` + l + `" password="` + b + `" protocol="1" connect="19" />` + "\n"
}
