package obfuscator

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type RollingKey struct {
	a, b, c, d   uint64
	pos          uint64
	counter      uint64
	mut          sync.Mutex
	lastMutation time.Time
}

func getVolatileContext() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	h := fnv.New64a()

	now := time.Now()
	h.Write([]byte(fmt.Sprintf("%d", now.UnixNano())))
	h.Write([]byte(fmt.Sprintf("%d", now.UnixMicro())))

	h.Write([]byte(fmt.Sprintf("%d", m.Alloc)))
	h.Write([]byte(fmt.Sprintf("%d", m.TotalAlloc)))
	h.Write([]byte(fmt.Sprintf("%d", m.Sys)))
	h.Write([]byte(fmt.Sprintf("%d", m.NumGC)))
	h.Write([]byte(fmt.Sprintf("%d", m.HeapAlloc)))
	h.Write([]byte(fmt.Sprintf("%d", m.HeapSys)))
	h.Write([]byte(fmt.Sprintf("%d", m.StackInuse)))

	h.Write([]byte(fmt.Sprintf("%d", runtime.NumGoroutine())))

	pc := make([]uintptr, 10)
	n := runtime.Callers(1, pc)
	if n > 0 {
		frames := runtime.CallersFrames(pc[:n])
		for {
			frame, more := frames.Next()
			h.Write([]byte(fmt.Sprintf("%d", frame.PC)))
			if !more {
				break
			}
		}
	}

	h.Write([]byte("volatile_context_marker"))

	result := h.Sum64()

	result ^= rotateLeft64(result, 17)
	result ^= rotateRight64(result, 31)

	return result
}

func gatherDeterministicEntropy() (uint64, uint64) {
	h := sha256.New()

	// System architecture info
	h.Write([]byte(runtime.Version()))
	h.Write([]byte(runtime.GOOS))
	h.Write([]byte(runtime.GOARCH))

	// Process-specific info
	if hostname, err := os.Hostname(); err == nil {
		h.Write([]byte(hostname))
	}

	// Extended environment variables
	for _, env := range []string{"HOME", "USER", "USERNAME", "USERPROFILE", "COMPUTERNAME", "PROCESSOR_IDENTIFIER", "SESSIONNAME"} {
		if val := os.Getenv(env); val != "" {
			h.Write([]byte(val))
		}
	}

	// Binary-specific entropy
	if exe, err := os.Executable(); err == nil {
		h.Write([]byte(exe))
		if info, err := os.Stat(exe); err == nil {
			h.Write([]byte(fmt.Sprintf("%d", info.Size())))
			h.Write([]byte(info.ModTime().String()))
		}
	}

	if wd, err := os.Getwd(); err == nil {
		h.Write([]byte(wd))
	}

	h.Write([]byte(fmt.Sprintf("%d", os.Getpid())))

	h.Write([]byte(fmt.Sprintf("%d", runtime.NumCPU())))
	h.Write([]byte(fmt.Sprintf("%d", runtime.NumGoroutine())))

	hash := h.Sum(nil)

	fnvHash := fnv.New64a()
	fnvHash.Write(hash[:16])
	seed1 := fnvHash.Sum64()

	fnvHash.Reset()
	fnvHash.Write(hash[16:])
	seed2 := fnvHash.Sum64()

	seed1 ^= rotateLeft64(seed2, 13)
	seed2 ^= rotateRight64(seed1, 7)

	return seed1, seed2
}

func gatherVolatileEntropy() (uint64, uint64) {
	h := sha256.New()

	now := time.Now()
	h.Write([]byte(now.String()))
	h.Write([]byte(fmt.Sprintf("%d", now.UnixNano())))
	h.Write([]byte(fmt.Sprintf("%d", now.Unix())))

	if wd, err := os.Getwd(); err == nil {
		h.Write([]byte(wd))
	}

	for _, env := range []string{"PATH", "TEMP", "TMP", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS"} {
		if val := os.Getenv(env); val != "" {
			h.Write([]byte(val))
		}
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	h.Write([]byte(fmt.Sprintf("%d%d%d%d%d%d%d",
		m.Alloc, m.TotalAlloc, m.Sys, m.HeapAlloc, m.HeapSys, m.StackInuse, m.NumGC)))

	h.Write([]byte(fmt.Sprintf("%d", os.Getpid())))
	h.Write([]byte(fmt.Sprintf("%d", runtime.NumGoroutine())))

	pc := make([]uintptr, 5)
	n := runtime.Callers(2, pc)
	if n > 0 {
		for i := 0; i < n; i++ {
			h.Write([]byte(fmt.Sprintf("%d", pc[i])))
		}
	}

	h.Write([]byte("volatile_entropy_generation"))

	hash := h.Sum(nil)

	fnvHash := fnv.New64a()
	fnvHash.Write(hash[:12])
	seed1 := fnvHash.Sum64()

	fnvHash.Reset()
	fnvHash.Write(hash[12:24])
	seed2 := fnvHash.Sum64()

	seed1 ^= rotateLeft64(seed2, 19)
	seed2 ^= rotateRight64(seed1, 41)

	return seed1, seed2
}

func NewRollingKey(seed1, seed2 uint64) *RollingKey {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%d%d", seed1, seed2)))
	seed3 := h.Sum64()

	h.Reset()
	h.Write([]byte(fmt.Sprintf("%d%d", seed2, seed3)))
	seed4 := h.Sum64()

	return &RollingKey{
		a:            seed1,
		b:            seed2,
		c:            seed3,
		d:            seed4,
		pos:          0,
		counter:      0,
		lastMutation: time.Now(),
	}
}

func NewRollingKeyFromEntropy() *RollingKey {
	seed1, seed2 := gatherDeterministicEntropy()
	return NewRollingKey(seed1, seed2)
}

func (rk *RollingKey) Next() uint8 {
	rk.mut.Lock()
	defer rk.mut.Unlock()

	if time.Since(rk.lastMutation) > 100*time.Millisecond {
		volatile := getVolatileContext()
		rk.a ^= volatile
		rk.b ^= volatile >> 32
		rk.c ^= volatile << 16
		rk.d ^= volatile >> 48
		rk.lastMutation = time.Now()
	}

	rk.counter++

	t1 := rk.a ^ (rk.b << 13)
	t2 := rk.b ^ (rk.c >> 17)
	t3 := rk.c ^ (rk.d << 5)
	t4 := rk.d ^ (rk.a >> 27)

	t1 ^= rk.pos * 0x9e3779b97f4a7c15 // Golden ratio multiplier
	t2 ^= rk.counter * 0xbf58476d1ce4e5b9

	mixed := t1 ^ rotateLeft64(t2, 23) ^ rotateRight64(t3, 17) ^ rotateLeft64(t4, 11)

	rk.a = rk.b ^ rotateLeft64(mixed, 31)
	rk.b = rk.c ^ (mixed * 0x94d049bb133111eb)
	rk.c = rk.d ^ rotateRight64(mixed, 43)
	rk.d = t1 ^ t2 ^ t3 ^ t4

	rk.pos++

	result := mixed ^ (mixed >> 32)
	result ^= result >> 16
	result ^= result >> 8

	return uint8(result)
}

func rotateLeft64(x uint64, k uint) uint64 {
	return (x << k) | (x >> (64 - k))
}

func rotateRight64(x uint64, k uint) uint64 {
	return (x >> k) | (x << (64 - k))
}

type ObfuscatedData struct {
	Data       []uint8
	Lens       []int
	Pads       []int
	Compressed bool
}

func secureClear(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

type VMOpcode uint8

const (
	OP_PUSH VMOpcode = 0x73
	OP_POP  VMOpcode = 0x2A
	OP_ADD  VMOpcode = 0x91
	OP_XOR  VMOpcode = 0x4E
	OP_LOAD VMOpcode = 0x67
	OP_JUMP VMOpcode = 0x1D
	OP_HALT VMOpcode = 0x8C
	OP_DUP  VMOpcode = 0x39
	OP_SWAP VMOpcode = 0x5B
)

type VMInstruction struct {
	opcode  VMOpcode
	operand int
	encoded bool
}

func (inst *VMInstruction) encode(key uint64) {
	if inst.encoded {
		return
	}

	inst.opcode = VMOpcode(uint8(inst.opcode) ^ uint8(key&0xFF))

	inst.operand ^= int((key >> 8) & 0xFFFFFF)

	inst.encoded = true
}

func (inst *VMInstruction) decode(key uint64) VMInstruction {
	if !inst.encoded {
		return *inst
	}

	decoded := VMInstruction{
		opcode:  VMOpcode(uint8(inst.opcode) ^ uint8(key&0xFF)),
		operand: inst.operand ^ int((key>>8)&0xFFFFFF),
		encoded: false,
	}

	return decoded
}

type StringVM struct {
	stack          []int
	pc             int
	code           []VMInstruction
	data           *ObfuscatedData
	opcodeHandlers map[VMOpcode]func(*StringVM, int) string
	encodeKey      uint64
}

func NewStringVM(data *ObfuscatedData) *StringVM {
	vm := &StringVM{
		stack:          make([]int, 0, 32),
		pc:             0,
		code:           make([]VMInstruction, 0),
		data:           data,
		opcodeHandlers: make(map[VMOpcode]func(*StringVM, int) string),
		encodeKey:      generateVMEncodeKey(data),
	}
	vm.initializeOpcodeHandlers()
	return vm
}

func generateVMEncodeKey(data *ObfuscatedData) uint64 {
	h := fnv.New64a()
	h.Write([]byte("vm_encode_key"))
	h.Write([]byte(fmt.Sprintf("%d", len(data.Data))))
	h.Write([]byte(fmt.Sprintf("%d", len(data.Lens))))

	if len(data.Data) > 0 {
		h.Write(data.Data[:min(16, len(data.Data))])
	}

	key := h.Sum64()
	return key ^ rotateLeft64(key, 23)
}

func (vm *StringVM) initializeOpcodeHandlers() {
	seed := getVolatileContext()
	rand.Seed(int64(seed))

	handlers := []struct {
		op VMOpcode
		fn func(*StringVM, int) string
	}{
		{OP_PUSH, func(vm *StringVM, operand int) string { return vm.handlePush(operand) }},
		{OP_POP, func(vm *StringVM, operand int) string { return vm.handlePop(operand) }},
		{OP_ADD, func(vm *StringVM, operand int) string { return vm.handleAdd(operand) }},
		{OP_XOR, func(vm *StringVM, operand int) string { return vm.handleXor(operand) }},
		{OP_LOAD, func(vm *StringVM, operand int) string { return vm.handleLoad(operand) }},
		{OP_JUMP, func(vm *StringVM, operand int) string { return vm.handleJump(operand) }},
		{OP_HALT, func(vm *StringVM, operand int) string { return vm.handleHalt(operand) }},
		{OP_DUP, func(vm *StringVM, operand int) string { return vm.handleDup(operand) }},
		{OP_SWAP, func(vm *StringVM, operand int) string { return vm.handleSwap(operand) }},
	}

	fakeOpcodes := []VMOpcode{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	for _, fakeOp := range fakeOpcodes {
		handlers = append(handlers, struct {
			op VMOpcode
			fn func(*StringVM, int) string
		}{
			fakeOp, func(vm *StringVM, operand int) string {
				vm.stack = append(vm.stack, operand^0xDEADBEEF)
				if len(vm.stack) > 1 {
					vm.stack = vm.stack[:len(vm.stack)-1]
				}
				return ""
			},
		})
	}

	for i := len(handlers) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		handlers[i], handlers[j] = handlers[j], handlers[i]
	}

	for _, h := range handlers {
		vm.opcodeHandlers[h.op] = h.fn
	}
}

func (vm *StringVM) push(value int) {
	vm.stack = append(vm.stack, value)
}

func (vm *StringVM) pop() int {
	if len(vm.stack) == 0 {
		return 0
	}
	value := vm.stack[len(vm.stack)-1]
	vm.stack = vm.stack[:len(vm.stack)-1]
	return value
}

func (vm *StringVM) peek() int {
	if len(vm.stack) == 0 {
		return 0
	}
	return vm.stack[len(vm.stack)-1]
}

func (vm *StringVM) handlePush(operand int) string {
	vm.push(operand)
	return ""
}

func (vm *StringVM) handlePop(operand int) string {
	vm.pop()
	return ""
}

func (vm *StringVM) handleAdd(operand int) string {
	b := vm.pop()
	a := vm.pop()
	vm.push(a + b)
	return ""
}

func (vm *StringVM) handleXor(operand int) string {
	b := vm.pop()
	a := vm.pop()
	vm.push(a ^ b)
	return ""
}

func (vm *StringVM) handleLoad(operand int) string {
	idx := vm.pop()
	if idx >= 0 && idx < len(vm.data.Lens) {
		return vm.loadString(idx)
	}
	return ""
}

func (vm *StringVM) handleJump(operand int) string {
	if vm.pop() != 0 {
		vm.pc = operand - 1
	}
	return ""
}

func (vm *StringVM) handleHalt(operand int) string {
	return ""
}

func (vm *StringVM) handleDup(operand int) string {
	vm.push(vm.peek())
	return ""
}

func (vm *StringVM) handleSwap(operand int) string {
	b := vm.pop()
	a := vm.pop()
	vm.push(b)
	vm.push(a)
	return ""
}

func (vm *StringVM) execute() string {
	for vm.pc < len(vm.code) {
		encodedInst := vm.code[vm.pc]

		inst := encodedInst.decode(vm.encodeKey)

		result := vm.obfuscatedDispatch(inst)
		if result != "" {
			return result
		}

		vm.pc++
	}
	return ""
}

func (vm *StringVM) obfuscatedDispatch(inst VMInstruction) string {
	opcodeHash := uint64(inst.opcode)
	opcodeHash ^= rotateLeft64(opcodeHash, 13)
	opcodeHash ^= rotateRight64(opcodeHash, 7)
	opcodeHash ^= vm.encodeKey

	switch opcodeHash % 3 {
	case 0:
		return vm.dispatchPath1(inst)
	case 1:
		return vm.dispatchPath2(inst)
	case 2:
		return vm.dispatchPath3(inst)
	}

	return ""
}

func (vm *StringVM) dispatchPath1(inst VMInstruction) string {
	if inst.opcode == OP_PUSH {
		return vm.handlePush(inst.operand)
	}
	if inst.opcode == OP_POP {
		return vm.handlePop(inst.operand)
	}
	if inst.opcode == OP_ADD {
		return vm.handleAdd(inst.operand)
	}
	if inst.opcode == OP_XOR {
		return vm.handleXor(inst.operand)
	}
	if inst.opcode == OP_LOAD {
		return vm.handleLoad(inst.operand)
	}
	if inst.opcode == OP_JUMP {
		return vm.handleJump(inst.operand)
	}
	if inst.opcode == OP_HALT {
		return vm.handleHalt(inst.operand)
	}
	if inst.opcode == OP_DUP {
		return vm.handleDup(inst.operand)
	}
	if inst.opcode == OP_SWAP {
		return vm.handleSwap(inst.operand)
	}
	return vm.handleUnknown(inst)
}

func (vm *StringVM) dispatchPath2(inst VMInstruction) string {
	if inst.opcode == OP_SWAP {
		return vm.handleSwap(inst.operand)
	}
	if inst.opcode == OP_DUP {
		return vm.handleDup(inst.operand)
	}
	if inst.opcode == OP_HALT {
		return vm.handleHalt(inst.operand)
	}
	if inst.opcode == OP_JUMP {
		return vm.handleJump(inst.operand)
	}
	if inst.opcode == OP_LOAD {
		return vm.handleLoad(inst.operand)
	}
	if inst.opcode == OP_XOR {
		return vm.handleXor(inst.operand)
	}
	if inst.opcode == OP_ADD {
		return vm.handleAdd(inst.operand)
	}
	if inst.opcode == OP_POP {
		return vm.handlePop(inst.operand)
	}
	if inst.opcode == OP_PUSH {
		return vm.handlePush(inst.operand)
	}
	return vm.handleUnknown(inst)
}

func (vm *StringVM) dispatchPath3(inst VMInstruction) string {
	if inst.opcode == OP_LOAD {
		return vm.handleLoad(inst.operand)
	}
	if inst.opcode == OP_PUSH {
		return vm.handlePush(inst.operand)
	}
	if inst.opcode == OP_XOR {
		return vm.handleXor(inst.operand)
	}
	if inst.opcode == OP_DUP {
		return vm.handleDup(inst.operand)
	}
	if inst.opcode == OP_ADD {
		return vm.handleAdd(inst.operand)
	}
	if inst.opcode == OP_HALT {
		return vm.handleHalt(inst.operand)
	}
	if inst.opcode == OP_POP {
		return vm.handlePop(inst.operand)
	}
	if inst.opcode == OP_SWAP {
		return vm.handleSwap(inst.operand)
	}
	if inst.opcode == OP_JUMP {
		return vm.handleJump(inst.operand)
	}
	return vm.handleUnknown(inst)
}

func (vm *StringVM) fallbackDispatch(inst VMInstruction) string {
	if handler, exists := vm.opcodeHandlers[inst.opcode]; exists {
		return handler(vm, inst.operand)
	}
	return vm.handleUnknown(inst)
}

func (vm *StringVM) handleUnknown(inst VMInstruction) string {
	vm.stack = append(vm.stack, int(inst.opcode)^inst.operand)
	if len(vm.stack) > 1 {
		vm.stack = vm.stack[:len(vm.stack)-1]
	}
	return ""
}

func (vm *StringVM) loadString(idx int) string {
	if idx >= len(vm.data.Lens) {
		return ""
	}

	start := 0
	for i := 0; i < idx; i++ {
		start += vm.data.Lens[i] + vm.data.Pads[i]
	}

	length := vm.data.Lens[idx]
	key := NewRollingKeyFromEntropy()

	for i := 0; i < start; i++ {
		key.Next()
	}

	decrypted := make([]byte, length)
	for i := 0; i < length; i++ {
		decrypted[i] = vm.data.Data[start+i] ^ key.Next()
	}

	var result string
	if vm.data.Compressed {
		reader := bytes.NewReader(decrypted)
		r, err := zlib.NewReader(reader)
		if err != nil {
			secureClear(decrypted)
			return ""
		}
		defer r.Close()

		var buf bytes.Buffer
		buf.ReadFrom(r)
		result = buf.String()
	} else {
		result = string(decrypted)
	}

	secureClear(decrypted)
	return result
}

func (vm *StringVM) insertRandomNoise(code []VMInstruction, generator *RandomOpcodeGenerator) []VMInstruction {
	result := make([]VMInstruction, 0)

	for _, inst := range code {
		result = append(result, inst)

		probability := generator.rng.Intn(100)
		probabilityThreshold := 70

		noiseInsertion := max(0, 1-max(0, probability-probabilityThreshold))
		noiseCount := (generator.rng.Intn(3) + 1) * noiseInsertion

		for j := 0; j < noiseCount; j++ {
			noise := generator.generateNoiseOperations(1)
			result = append(result, noise...)
		}
	}

	return result
}

func max(a, b int) int {
	return a + (b-a)*(1&((b-a)>>31))
}

func abs(x int) int {
	mask := x >> 31
	return (x + mask) ^ mask
}

type RandomOpcodeGenerator struct {
	rng *rand.Rand
}

func NewRandomOpcodeGenerator(seed int64) *RandomOpcodeGenerator {
	return &RandomOpcodeGenerator{
		rng: rand.New(rand.NewSource(seed)),
	}
}

func (rog *RandomOpcodeGenerator) generateValueProduction(targetValue int) []VMInstruction {
	operations := make([]VMInstruction, 0)

	sequenceLength := rog.rng.Intn(11) + 5

	intermediateValues := rog.generateRandomIntermediates(targetValue, sequenceLength)

	for _, val := range intermediateValues {
		rog.appendRandomOpcodes(&operations, val)
	}

	rog.appendCombinationOpcodes(&operations, len(intermediateValues))

	return operations
}

func (rog *RandomOpcodeGenerator) generateRandomIntermediates(target int, count int) []int {
	intermediates := make([]int, 0)

	remaining := target

	for i := 0; i < count-1; i++ {
		maxVal := remaining / (count - i)
		val := rog.rng.Intn(maxVal + 1)
		intermediates = append(intermediates, val)
		remaining -= val
	}

	intermediates = append(intermediates, remaining)

	return intermediates
}

func (rog *RandomOpcodeGenerator) appendRandomOpcodes(operations *[]VMInstruction, value int) {
	randomA := rog.rng.Intn(256)

	transformed := value ^ randomA

	*operations = append(*operations, VMInstruction{OP_PUSH, transformed, false})
	*operations = append(*operations, VMInstruction{OP_PUSH, randomA, false})
	*operations = append(*operations, VMInstruction{OP_XOR, 0, false})

	rog.appendNoiseOpcodes(operations)
}

func (rog *RandomOpcodeGenerator) appendCombinationOpcodes(operations *[]VMInstruction, count int) {
	for i := 0; i < count-1; i++ {
		rog.appendNoiseOpcodes(operations)

		*operations = append(*operations, VMInstruction{OP_ADD, 0, false})

		rog.appendNoiseOpcodes(operations)
	}
}

func (rog *RandomOpcodeGenerator) appendNoiseOpcodes(operations *[]VMInstruction) {

	noiseCount := rog.rng.Intn(3) + 1

	for i := 0; i < noiseCount; i++ {
		randomVal := rog.rng.Intn(256)

		*operations = append(*operations, VMInstruction{OP_PUSH, randomVal, false})
		*operations = append(*operations, VMInstruction{OP_PUSH, randomVal, false})
		*operations = append(*operations, VMInstruction{OP_XOR, 0, false})
		*operations = append(*operations, VMInstruction{OP_POP, 0, false})

		*operations = append(*operations, VMInstruction{OP_PUSH, rog.rng.Intn(256), false})
		*operations = append(*operations, VMInstruction{OP_DUP, 0, false})
		*operations = append(*operations, VMInstruction{OP_SWAP, 0, false})
		*operations = append(*operations, VMInstruction{OP_POP, 0, false})
		*operations = append(*operations, VMInstruction{OP_POP, 0, false})
	}
}

func (rog *RandomOpcodeGenerator) generateNoiseOperations(count int) []VMInstruction {
	operations := make([]VMInstruction, 0)

	for i := 0; i < count; i++ {
		rog.appendNoiseOpcodes(&operations)
	}

	return operations
}

func (vm *StringVM) generateBytecode(index int) []VMInstruction {
	seed := getVolatileContext()
	generator := NewRandomOpcodeGenerator(int64(seed))

	code := make([]VMInstruction, 0)

	noiseCount := generator.rng.Intn(5) + 3
	initialNoise := generator.generateNoiseOperations(noiseCount)
	code = append(code, initialNoise...)

	obfuscated := index ^ int(seed&0xFF)

	obfuscatedOps := generator.generateValueProduction(obfuscated)
	code = append(code, obfuscatedOps...)

	seedMask := int(seed & 0xFF)
	seedOps := generator.generateValueProduction(seedMask)
	code = append(code, seedOps...)

	code = append(code, VMInstruction{OP_XOR, 0, false})

	midNoise := generator.generateNoiseOperations(generator.rng.Intn(3) + 1)
	code = append(code, midNoise...)

	code = append(code, VMInstruction{OP_LOAD, 0, false})
	code = append(code, VMInstruction{OP_HALT, 0, false})

	code = vm.insertRandomNoise(code, generator)

	for i := range code {
		code[i].encode(vm.encodeKey)
	}

	return code
}

func (vm *StringVM) executeStringAccess(index int) string {
	vm.code = vm.generateBytecode(index)
	vm.pc = 0
	vm.stack = vm.stack[:0]
	return vm.execute()
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
		j := (i*17 + 23) % (i + 1)
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

	var result string
	if ss.data.Compressed {
		reader := bytes.NewReader(decrypted)
		r, err := zlib.NewReader(reader)
		if err != nil {
			secureClear(decrypted)
			return ""
		}
		defer r.Close()

		var buf bytes.Buffer
		buf.ReadFrom(r)
		result = buf.String()
	} else {
		result = string(decrypted)
	}

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

func encryptCompressedString(s string, key *RollingKey) []uint8 {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()

	compressed := buf.Bytes()
	encrypted := make([]uint8, len(compressed))
	for i, b := range compressed {
		encrypted[i] = uint8(b) ^ key.Next()
	}
	return encrypted
}

func GenerateObfuscatedData(inputStrings []string) *ObfuscatedData {
	return GenerateObfuscatedDataWithOptions(inputStrings, false)
}

func GenerateObfuscatedDataWithOptions(inputStrings []string, compressed bool) *ObfuscatedData {
	volatileSeed1, volatileSeed2 := gatherVolatileEntropy()
	rand.Seed(int64(volatileSeed1 ^ volatileSeed2))

	data := &ObfuscatedData{
		Data:       make([]uint8, 0),
		Lens:       make([]int, len(inputStrings)),
		Pads:       make([]int, len(inputStrings)),
		Compressed: compressed,
	}

	key := NewRollingKeyFromEntropy()

	for i, s := range inputStrings {
		var encrypted []uint8
		if compressed {
			encrypted = encryptCompressedString(s, key)
		} else {
			encrypted = encryptString(s, key)
		}

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

	obfKey := generateObfuscationKey(data)
	rand.Seed(int64(obfKey))

	obfuscatedData := make([]uint8, len(data.Data))
	for i, b := range data.Data {
		obfuscatedData[i] = b ^ uint8((obfKey>>uint(i%8))&0xFF)
	}

	numChunks := rand.Intn(6) + 3

	chunkSizes := make([]int, numChunks)
	remaining := len(obfuscatedData)
	for i := 0; i < numChunks-1; i++ {
		maxSize := remaining / (numChunks - i)
		minSize := max(1, remaining-(numChunks-i-1)*maxSize)
		chunkSizes[i] = rand.Intn(maxSize-minSize+1) + minSize
		remaining -= chunkSizes[i]
	}
	chunkSizes[numChunks-1] = remaining

	chunks := make([][]uint8, numChunks)
	offset := 0
	for i := 0; i < numChunks; i++ {
		end := offset + chunkSizes[i]
		if end > len(obfuscatedData) {
			end = len(obfuscatedData)
		}
		chunks[i] = obfuscatedData[offset:end]
		offset = end
	}

	prefixes := []string{"config", "module", "header", "meta", "aux", "core", "sys", "app", "lib", "data", "info", "buf", "mem", "ctx", "env", "proc", "svc", "mgr", "util", "misc"}
	suffixes := []string{"Data", "Info", "Bytes", "Buffer", "Config", "Table", "Array", "Block", "Segment", "Chunk", "Region", "Space", "Store", "Cache", "Pool"}

	generateRandomVarName := func() string {
		prefix := prefixes[rand.Intn(len(prefixes))]
		suffix := suffixes[rand.Intn(len(suffixes))]
		return prefix + suffix
	}

	chunkVars := make([]string, numChunks)
	usedNames := make(map[string]bool)
	for i := 0; i < numChunks; i++ {
		for {
			name := generateRandomVarName()
			if !usedNames[name] {
				chunkVars[i] = name
				usedNames[name] = true
				break
			}
		}
	}

	var lensVar, padsVar string
	for {
		lensVar = generateRandomVarName()
		if !usedNames[lensVar] {
			usedNames[lensVar] = true
			break
		}
	}
	for {
		padsVar = generateRandomVarName()
		if !usedNames[padsVar] {
			usedNames[padsVar] = true
			break
		}
	}

	numDecoys := rand.Intn(3) + 2
	decoyVars := make([]string, numDecoys)
	for i := 0; i < numDecoys; i++ {
		for {
			name := generateRandomVarName()
			if !usedNames[name] {
				decoyVars[i] = name
				usedNames[name] = true
				break
			}
		}
	}

	for i, chunk := range chunks {
		sb.WriteString(fmt.Sprintf("var %s = []uint8{", chunkVars[i]))

		lineBreak := rand.Intn(16) + 8
		for j, b := range chunk {
			if j > 0 && j%lineBreak == 0 {
				sb.WriteString("\n\t")
			}
			sb.WriteString(fmt.Sprintf("0x%02x", b))
			if j < len(chunk)-1 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("}\n\n")
	}

	for _, decoyVar := range decoyVars {
		decoySize := rand.Intn(50) + 10
		sb.WriteString(fmt.Sprintf("var %s = []uint8{", decoyVar))
		for j := 0; j < decoySize; j++ {
			if j > 0 && j%12 == 0 {
				sb.WriteString("\n\t")
			}
			sb.WriteString(fmt.Sprintf("0x%02x", rand.Intn(256)))
			if j < decoySize-1 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString("}\n\n")

		sb.WriteString(fmt.Sprintf("func process%s() {\n", decoyVar))
		sb.WriteString(fmt.Sprintf("\tfor i := range %s {\n", decoyVar))
		sb.WriteString(fmt.Sprintf("\t\t%s[i] ^= 0x%02x\n", decoyVar, rand.Intn(256)))
		sb.WriteString("\t}\n")
		sb.WriteString("}\n\n")
	}

	lengthOffset := int(obfKey & 0xFFFF)
	lengthMask := int((obfKey >> 16) & 0xFF)

	sb.WriteString(fmt.Sprintf("var %s = []int{", lensVar))
	for i, l := range data.Lens {
		if i > 0 {
			sb.WriteString(", ")
		}
		obfuscatedLen := (l + lengthOffset) ^ lengthMask
		sb.WriteString(fmt.Sprintf("%d", obfuscatedLen))
	}
	sb.WriteString("}\n\n")

	padKey := rotateLeft64(obfKey, 16)
	padMask := int((padKey >> 8) & 0xFF)

	sb.WriteString(fmt.Sprintf("var %s = []int{", padsVar))
	for i, p := range data.Pads {
		if i > 0 {
			sb.WriteString(", ")
		}
		obfuscatedPad := (p ^ int(padKey&0xFF)) + padMask
		sb.WriteString(fmt.Sprintf("%d", obfuscatedPad))
	}
	sb.WriteString("}\n\n")

	constantNames := make([]string, 5)
	for i := 0; i < 5; i++ {
		for {
			name := generateRandomVarName()
			if !usedNames[name] {
				constantNames[i] = name
				usedNames[name] = true
				break
			}
		}
	}

	sb.WriteString(fmt.Sprintf("var %s = %d\n", constantNames[0], lengthOffset))
	sb.WriteString(fmt.Sprintf("var %s = %d\n", constantNames[1], lengthMask))
	sb.WriteString(fmt.Sprintf("var %s = uint64(%d)\n", constantNames[2], obfKey))
	sb.WriteString(fmt.Sprintf("var %s = uint64(%d)\n", constantNames[3], padKey))
	sb.WriteString(fmt.Sprintf("var %s = %d\n", constantNames[4], padMask))
	sb.WriteString(fmt.Sprintf("var useCompression = %t\n\n", data.Compressed))

	reconstructOrder := make([]int, numChunks)
	for i := 0; i < numChunks; i++ {
		reconstructOrder[i] = i
	}
	for i := len(reconstructOrder) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		reconstructOrder[i], reconstructOrder[j] = reconstructOrder[j], reconstructOrder[i]
	}

	sb.WriteString("func GetObfuscatedData() *obfuscator.ObfuscatedData {\n")

	sb.WriteString("\t// Initialize decoy processing\n")
	sb.WriteString(fmt.Sprintf("\tdecoySum := 0\n"))
	for _, decoyVar := range decoyVars {
		sb.WriteString(fmt.Sprintf("\tdecoySum += len(%s)\n", decoyVar))
	}
	sb.WriteString("\t_ = decoySum\n\n")

	sb.WriteString("\t// Reconstruct data in randomized order\n")
	sb.WriteString(fmt.Sprintf("\tcombined := make([]uint8, 0)\n"))

	sb.WriteString(fmt.Sprintf("\ttempChunks := make([][]uint8, %d)\n", numChunks))
	for i, origIndex := range reconstructOrder {
		sb.WriteString(fmt.Sprintf("\ttempChunks[%d] = %s\n", origIndex, chunkVars[i]))
	}

	sb.WriteString("\t// Reassemble in correct order\n")
	sb.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", numChunks))
	sb.WriteString("\t\tcombined = append(combined, tempChunks[i]...)\n")
	sb.WriteString("\t}\n\n")

	sb.WriteString("\t// Apply deobfuscation with multiple passes\n")
	sb.WriteString("\tfor pass := 0; pass < 2; pass++ {\n")
	sb.WriteString("\t\tfor i := range combined {\n")
	sb.WriteString(fmt.Sprintf("\t\t\tif pass == 0 {\n"))
	sb.WriteString(fmt.Sprintf("\t\t\t\tcombined[i] ^= uint8((%s>>uint(i%%8))&0xFF)\n", constantNames[2]))
	sb.WriteString("\t\t\t}\n")
	sb.WriteString("\t\t}\n")
	sb.WriteString("\t}\n\n")

	sb.WriteString("\t// Deobfuscate lengths with multiple transformations\n")
	sb.WriteString(fmt.Sprintf("\tlens := make([]int, len(%s))\n", lensVar))
	sb.WriteString(fmt.Sprintf("\tfor i, l := range %s {\n", lensVar))
	sb.WriteString(fmt.Sprintf("\t\tlens[i] = (l ^ %s) - %s\n", constantNames[1], constantNames[0]))
	sb.WriteString("\t}\n\n")

	sb.WriteString("\t// Deobfuscate padding with multiple transformations\n")
	sb.WriteString(fmt.Sprintf("\tpads := make([]int, len(%s))\n", padsVar))
	sb.WriteString(fmt.Sprintf("\tfor i, p := range %s {\n", padsVar))
	sb.WriteString(fmt.Sprintf("\t\tpads[i] = (p - %s) ^ int(%s&0xFF)\n", constantNames[4], constantNames[3]))
	sb.WriteString("\t}\n\n")

	sb.WriteString("\treturn &obfuscator.ObfuscatedData{Data: combined, Lens: lens, Pads: pads, Compressed: useCompression}\n")
	sb.WriteString("}\n\n")

	for i := 0; i < numDecoys; i++ {
		funcName := fmt.Sprintf("Get%sData", decoyVars[i])
		sb.WriteString(fmt.Sprintf("func %s() []uint8 {\n", funcName))
		sb.WriteString(fmt.Sprintf("\tresult := make([]uint8, len(%s))\n", decoyVars[i]))
		sb.WriteString(fmt.Sprintf("\tcopy(result, %s)\n", decoyVars[i]))
		sb.WriteString(fmt.Sprintf("\tfor i := range result {\n"))
		sb.WriteString(fmt.Sprintf("\t\tresult[i] ^= 0x%02x\n", rand.Intn(256)))
		sb.WriteString("\t}\n")
		sb.WriteString("\treturn result\n")
		sb.WriteString("}\n\n")
	}

	sb.WriteString("func GetStringStack() *obfuscator.StringStack {\n")
	sb.WriteString("\treturn obfuscator.NewStringStack(GetObfuscatedData())\n")
	sb.WriteString("}\n")

	return sb.String()
}

func generateObfuscationKey(data *ObfuscatedData) uint64 {
	h := fnv.New64a()

	h.Write([]byte(fmt.Sprintf("%d", len(data.Data))))
	h.Write([]byte(fmt.Sprintf("%d", len(data.Lens))))
	h.Write([]byte(fmt.Sprintf("%t", data.Compressed)))

	if len(data.Data) > 0 {
		h.Write(data.Data[:min(32, len(data.Data))])
	}

	for _, l := range data.Lens {
		h.Write([]byte(fmt.Sprintf("%d", l)))
	}

	key := h.Sum64()

	key ^= rotateLeft64(key, 13)
	key ^= rotateRight64(key, 7)

	return key
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Obfuscator struct {
	stack         *StringStack
	vm            *StringVM
	decryptedPool [][]byte
	decoyDepth    int
}

func NewObfuscator(data *ObfuscatedData) *Obfuscator {
	return &Obfuscator{
		stack:         NewStringStack(data),
		vm:            NewStringVM(data),
		decryptedPool: make([][]byte, 0),
		decoyDepth:    rand.Intn(3) + 1,
	}
}

func (o *Obfuscator) decoyAccess() {
	for i := 0; i < o.decoyDepth; i++ {
		o.stack.Push(rand.Intn(10))
		_ = o.stack.Pop()
	}
}

func (o *Obfuscator) Get(steps int) string {
	o.decoyAccess()
	actualIndex := steps % len(o.vm.data.Lens)

	result := o.vm.executeStringAccess(actualIndex)

	resultBytes := []byte(result)
	o.decryptedPool = append(o.decryptedPool, resultBytes)

	return result
}

func (o *Obfuscator) GetInPlace(steps int) []byte {
	o.decoyAccess()
	actualIndex := steps % len(o.vm.data.Lens)

	result := o.vm.executeStringAccess(actualIndex)
	resultBytes := *(*[]byte)(unsafe.Pointer(&result))
	return resultBytes
}

func (o *Obfuscator) Reset() {
	o.stack.position = 0
	o.decoyDepth = rand.Intn(3) + 1
}

func (o *Obfuscator) Clear() {
	for _, data := range o.decryptedPool {
		secureClear(data)
	}
	o.decryptedPool = o.decryptedPool[:0]
	runtime.GC()
}

func (o *Obfuscator) GetBytecode(steps int) []VMInstruction {
	actualIndex := steps % len(o.vm.data.Lens)
	return o.vm.generateBytecode(actualIndex)
}

func (inst VMInstruction) String() string {
	opcodeNames := map[VMOpcode]string{
		OP_PUSH: "PUSH",
		OP_POP:  "POP",
		OP_ADD:  "ADD",
		OP_XOR:  "XOR",
		OP_LOAD: "LOAD",
		OP_JUMP: "JUMP",
		OP_HALT: "HALT",
		OP_DUP:  "DUP",
		OP_SWAP: "SWAP",
	}

	if name, exists := opcodeNames[inst.opcode]; exists {
		encodedStr := ""
		if inst.encoded {
			encodedStr = "[E]"
		}
		return fmt.Sprintf("%s %d%s", name, inst.operand, encodedStr)
	}
	return fmt.Sprintf("UNKNOWN(0x%02x) %d", inst.opcode, inst.operand)
}
