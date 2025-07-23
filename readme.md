# stackobf

a string obfuscation system designed for redteam/maldev usage. this project is meant to demonstrate automated obfuscation of sensitive strings (like api names, system calls, etc.) that remain completely encrypted when the binary is not running, with no expensive hashing operations and dynamic entropy gathering from the target system. as well as a simple API to make accessing the strings in your own projects easy and painless, this is a very common method employed by threat actors to make reverse engineering and static analysis of malware harder. 

## how to use

```bash
go mod tidy 
# place your sensitive strings in cmd/input.txt (one per line)
# see cmd/input.txt for an example (all nt* prefixed syscalls from ntdll)

# to generate obfuscated strings
cd cmd
go run main.go 

# this creates obf.go with the obfuscated data
# in your project, import and use:
import "github.com/carved4/stackobf/obfuscator"

## use the generated obfuscated data
data := GetObfuscatedData()
obf := obfuscator.NewObfuscator(data)

## access strings via vm bytecode execution
apiCall := obf.Get(2)        ## navigate and retrieve without obvious lookups
process := obf.Get(1)        ## next string via stack operations
thread := obf.Get(3)         ## another string

## get bytecode for debugging/analysis
bytecode := obf.GetBytecode(1)  ## shows vm operations used for retrieval

## in-place decryption (no gc tracking)
inPlaceBytes := obf.GetInPlace(1)  ## direct byte access

obf.Clear()  ## securely clear decrypted strings from memory
```

> at build time, you should use go build -ldflags="-w -s -buildid=" -trimpath -o bin
> this will make reverse engineering harder 

## technical details

rolling fibonacci key with position-influenced sequences for encryption. we gather dynamic entropy from the target system's environment (hostname, user, runtime stats, etc.) without using syscalls to ensure cross-platform compatibility. strings are encrypted using xor with a rolling key and interleaved with random padding to break patterns. the vm-based access system executes truly random bytecode sequences instead of direct string lookups, making it exponentially harder to correlate access patterns with actual string content. when strings are decrypted, they're stored in a secure pool that can be cleared with obf.Clear() to prevent forensic recovery. deterministic entropy ensures consistent decryption while volatile entropy provides randomness for padding generation. advanced evasion features include volatile key mutation (keys re-roll every 100ms using runtime context), stack-smashing resistance (randomized decoy access patterns), optional zlib compression before encryption, pure in-place decryption (GetInPlace() method with no gc tracking), and truly random vm bytecode execution. the vm uses dynamic function pointer dispatch with randomized handler order, making reverse engineering significantly harder. each string access generates up to 1700+ unique vm operations through mathematical decomposition without conditional logic (no if/else statements in opcode generation). random opcode generation uses mathematical transformations to ensure correctness while maintaining randomness. noise insertion uses mathematical probability without conditional logic, generating mathematically neutral operations that cancel out. demo output shows actual vm operation chains like "PUSH 217 -> PUSH 217 -> XOR 0 -> ... +1167 ops" for each string retrieval. 

## static analysis resistance

heavily randomized code generation makes automated static analysis tools significantly less effective. instead of predictable 3-part data arrays, we generate 3-8 variable-sized chunks with completely randomized variable names (combinations of 20 prefixes + 15 suffixes like "configData", "sysBuffer", "procRegion", etc.). decoy data arrays and fake reconstruction functions are automatically generated to confuse pattern recognition - each compilation creates 2-4 decoy variables with their own processing functions that look legitimate but serve no real purpose. data reconstruction order is randomized on each compilation, so chunks are assembled in different sequences every time, breaking static analysis tools that expect consistent patterns. multiple transformation passes obscure the actual deobfuscation logic - lengths and padding use layered xor and addition operations instead of simple offsets. constant names are randomized across compilations, so there's no consistent "configMask" or "initOffset" to search for. the generated stub code varies dramatically between compilations, making it impossible to write generic decoding tools. this forces reverse engineers to manually analyze each binary instead of using automated pattern matching, significantly increasing analysis time and complexity.

this technique could be extended with additional vm opcodes, self-modifying bytecode, or hardware-specific instruction variants! feel free to submit PRs to contribute :3
