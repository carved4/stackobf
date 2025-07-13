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

# in your project, import and use:
import "github.com/carved4/stackobf/obfuscator"

data := GetObfuscatedData()
obf := obfuscator.NewObfuscator(data)

apiCall := obf.Get(2)  # navigate and retrieve without obvious lookups
process := obf.Get(1)  # next string via stack operations
thread := obf.Get(3)   # another string

obf.Clear()  # securely clear decrypted strings from memory
```

## technical details

rolling fibonacci key with position-influenced sequences for encryption. we gather dynamic entropy from the target system's environment (hostname, user, runtime stats, etc.) without using syscalls to ensure cross-platform compatibility. strings are encrypted using xor with a rolling key and interleaved with random padding to break patterns. the stack-based access system uses mathematical operations instead of direct string lookups, making it harder to correlate access patterns with actual string content. when strings are decrypted, they're stored in a secure pool that can be cleared with obf.Clear() to prevent forensic recovery. deterministic entropy ensures consistent decryption while volatile entropy provides randomness for padding generation. this is a minimal demonstration for educational purposes. the technique could be extended with additional layers like polymorphic key generation, anti-debugging checks etc etc. feel free to submit PRs to make it better, or let me know if it proves useful in any of your projects! 