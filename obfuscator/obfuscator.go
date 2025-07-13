package obfuscator

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"
)

type RollingKey struct {
	a, b uint64
	pos  uint64
}

func gatherDeterministicEntropy() (uint64, uint64) {
	h := sha256.New()
	
	h.Write([]byte(runtime.Version()))
	h.Write([]byte(runtime.GOOS))
	h.Write([]byte(runtime.GOARCH))
	
	if hostname, err := os.Hostname(); err == nil {
		h.Write([]byte(hostname))
	}
	
	for _, env := range []string{"HOME", "USER", "USERNAME", "USERPROFILE"} {
		if val := os.Getenv(env); val != "" {
			h.Write([]byte(val))
		}
	}
	
	hash := h.Sum(nil)
	
	fnvHash := fnv.New64a()
	fnvHash.Write(hash[:16])
	seed1 := fnvHash.Sum64()
	
	fnvHash.Reset()
	fnvHash.Write(hash[16:])
	seed2 := fnvHash.Sum64()
	
	return seed1, seed2
}

func gatherVolatileEntropy() (uint64, uint64) {
	h := sha256.New()
	
	h.Write([]byte(time.Now().String()))
	
	if wd, err := os.Getwd(); err == nil {
		h.Write([]byte(wd))
	}
	
	for _, env := range []string{"PATH", "TEMP", "TMP"} {
		if val := os.Getenv(env); val != "" {
			h.Write([]byte(val))
		}
	}
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	h.Write([]byte(fmt.Sprintf("%d%d%d", m.Alloc, m.TotalAlloc, m.Sys)))
	
	hash := h.Sum(nil)
	
	fnvHash := fnv.New64a()
	fnvHash.Write(hash[:16])
	seed1 := fnvHash.Sum64()
	
	fnvHash.Reset()
	fnvHash.Write(hash[16:])
	seed2 := fnvHash.Sum64()
	
	return seed1, seed2
}

func NewRollingKey(seed1, seed2 uint64) *RollingKey {
	return &RollingKey{a: seed1, b: seed2, pos: 0}
}

func NewRollingKeyFromEntropy() *RollingKey {
	seed1, seed2 := gatherDeterministicEntropy()
	return NewRollingKey(seed1, seed2)
}

func (rk *RollingKey) Next() uint8 {
	next := (rk.a + rk.b + rk.pos) % 256
	rk.a, rk.b = rk.b, next
	rk.pos++
	return uint8(next)
}

type ObfuscatedData struct {
	Data []uint8
	Lens []int
	Pads []int
}

func secureClear(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

type StringStack struct {
	data     *ObfuscatedData
	indices  []int
	position int
}

func NewStringStack(data *ObfuscatedData) *StringStack {
	indices := make([]int, len(data.Lens))
	for i := range indices {
		indices[i] = i
	}
	
	for i := len(indices) - 1; i > 0; i-- {
		j := (i * 17 + 23) % (i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}
	
	return &StringStack{
		data:     data,
		indices:  indices,
		position: 0,
	}
}

func (ss *StringStack) Push(steps int) {
	ss.position = (ss.position + steps) % len(ss.indices)
}

func (ss *StringStack) Pop() string {
	if ss.position < 0 || ss.position >= len(ss.indices) {
		return ""
	}
	
	idx := ss.indices[ss.position]
	ss.position = (ss.position + 1) % len(ss.indices)
	
	return ss.decrypt(idx)
}

func (ss *StringStack) decrypt(idx int) string {
	if idx >= len(ss.data.Lens) {
		return ""
	}
	
	start := 0
	for i := 0; i < idx; i++ {
		start += ss.data.Lens[i] + ss.data.Pads[i]
	}
	
	length := ss.data.Lens[idx]
	key := NewRollingKeyFromEntropy()
	
	for i := 0; i < start; i++ {
		key.Next()
	}
	
	decrypted := make([]byte, length)
	for i := 0; i < length; i++ {
		decrypted[i] = ss.data.Data[start+i] ^ key.Next()
	}
	
	result := string(decrypted)
	secureClear(decrypted)
	
	return result
}

func encryptString(s string, key *RollingKey) []uint8 {
	encrypted := make([]uint8, len(s))
	for i, b := range []byte(s) {
		encrypted[i] = uint8(b) ^ key.Next()
	}
	return encrypted
}

func GenerateObfuscatedData(inputStrings []string) *ObfuscatedData {
	volatileSeed1, volatileSeed2 := gatherVolatileEntropy()
	rand.Seed(int64(volatileSeed1 ^ volatileSeed2))
	
	data := &ObfuscatedData{
		Data: make([]uint8, 0),
		Lens: make([]int, len(inputStrings)),
		Pads: make([]int, len(inputStrings)),
	}
	
	key := NewRollingKeyFromEntropy()
	
	for i, s := range inputStrings {
		encrypted := encryptString(s, key)
		
		padLen := rand.Intn(8) + 1
		padding := make([]uint8, padLen)
		for j := range padding {
			padding[j] = uint8(rand.Intn(256))
		}
		
		data.Data = append(data.Data, encrypted...)
		data.Data = append(data.Data, padding...)
		data.Lens[i] = len(encrypted)
		data.Pads[i] = padLen
		
		for j := 0; j < padLen; j++ {
			key.Next()
		}
	}
	
	return data
}

func GenerateStub(data *ObfuscatedData) string {
	var sb strings.Builder
	
	sb.WriteString("package main\n\n")
	sb.WriteString("import \"github.com/carved4/stackobf/obfuscator\"\n\n")
	
	sb.WriteString("var obfData = []uint8{\n\t")
	for i, b := range data.Data {
		if i > 0 && i%16 == 0 {
			sb.WriteString("\n\t")
		}
		sb.WriteString(fmt.Sprintf("0x%02x, ", b))
	}
	sb.WriteString("\n}\n\n")
	
	sb.WriteString("var obfLens = []int{")
	for i, l := range data.Lens {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%d", l))
	}
	sb.WriteString("}\n\n")
	
	sb.WriteString("var obfPads = []int{")
	for i, p := range data.Pads {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%d", p))
	}
	sb.WriteString("}\n\n")
	
	sb.WriteString("func GetObfuscatedData() *obfuscator.ObfuscatedData {\n")
	sb.WriteString("\treturn &obfuscator.ObfuscatedData{Data: obfData, Lens: obfLens, Pads: obfPads}\n")
	sb.WriteString("}\n\n")
	
	sb.WriteString("func GetStringStack() *obfuscator.StringStack {\n")
	sb.WriteString("\treturn obfuscator.NewStringStack(GetObfuscatedData())\n")
	sb.WriteString("}\n")
	
	return sb.String()
}

type Obfuscator struct {
	stack         *StringStack
	decryptedPool [][]byte
}

func NewObfuscator(data *ObfuscatedData) *Obfuscator {
	return &Obfuscator{
		stack:         NewStringStack(data),
		decryptedPool: make([][]byte, 0),
	}
}

func (o *Obfuscator) Get(steps int) string {
	o.stack.Push(steps)
	result := o.stack.Pop()
	
	resultBytes := []byte(result)
	o.decryptedPool = append(o.decryptedPool, resultBytes)
	
	return result
}

func (o *Obfuscator) Reset() {
	o.stack.position = 0
}

func (o *Obfuscator) Clear() {
	for _, data := range o.decryptedPool {
		secureClear(data)
	}
	o.decryptedPool = o.decryptedPool[:0]
	runtime.GC()
} 