package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/carved4/stackobf/obfuscator"
)

func main() {
	var inputPath string
	if wd, err := os.Getwd(); err == nil {
		if strings.HasSuffix(wd, "cmd") || strings.HasSuffix(wd, "cmd/") {
			inputPath = "input.txt"
		} else {
			inputPath = "cmd/input.txt"
		}
	} else {
		if _, err := os.Stat("input.txt"); err == nil {
			inputPath = "input.txt"
		} else {
			inputPath = "cmd/input.txt"
		}
	}

	file, err := os.Open(inputPath)
	if err != nil {
		fmt.Printf("[-] error opening %s: %v\n", inputPath, err)
		return
	}
	defer file.Close()

	var inputStrings []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			inputStrings = append(inputStrings, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[-] error reading input.txt: %v\n", err)
		return
	}

	fmt.Printf("[+] generating obfuscated data for %d strings...\n", len(inputStrings))
	start := time.Now()
	data := obfuscator.GenerateObfuscatedDataWithOptions(inputStrings, true)
	genTime := time.Since(start)

	stub := obfuscator.GenerateStub(data)

	stubFile, err := os.Create("obf.go")
	if err != nil {
		fmt.Printf("[-] error creating stub file: %v\n", err)
		return
	}
	defer stubFile.Close()

	_, err = stubFile.WriteString(stub)
	if err != nil {
		fmt.Printf("[-] error writing stub: %v\n", err)
		return
	}

	fmt.Println("[+] generated obf.go")
	fmt.Printf("[+] performance: generation took %v for %d bytes (compressed: %t)\n", genTime, len(data.Data), data.Compressed)

	fmt.Println("[+] demonstration of usage :3:")
	obf := obfuscator.NewObfuscator(data)

	fmt.Println("[+] accessing strings via vm bytecode execution:")
	accessStart := time.Now()

	for i := 0; i <= 10; i++ {
		bytecode := obf.GetBytecode(i)
		result := obf.Get(i)

		fmt.Printf("[+] %s\n", result)
		fmt.Printf("    vm: %d ops [", len(bytecode))

		if len(bytecode) > 5 {
			for j := 0; j < 3; j++ {
				if j > 0 {
					fmt.Printf(" -> ")
				}
				fmt.Printf("%s", bytecode[j].String())
			}
			fmt.Printf(" -> ... +%d ops]\n", len(bytecode)-3)
		} else {
			for j, op := range bytecode {
				if j > 0 {
					fmt.Printf(" -> ")
				}
				fmt.Printf("%s", op.String())
			}
			fmt.Printf("]\n")
		}
	}

	accessTime := time.Since(accessStart)

	accessedCount := 11
	fmt.Printf("[+] performance: accessed %d strings in %v (avg: %v per string)\n",
		accessedCount, accessTime, accessTime/time.Duration(accessedCount))

	fmt.Println("[+] testing in-place decryption (no gc tracking):")
	inPlaceStart := time.Now()
	inPlaceBytes := obf.GetInPlace(1)
	inPlaceTime := time.Since(inPlaceStart)
	fmt.Printf("[+] in-place result: %s (took %v)\n", string(inPlaceBytes), inPlaceTime)

	fmt.Println("[+] clearing decrypted strings from memory...")
	clearStart := time.Now()
	obf.Clear()
	clearTime := time.Since(clearStart)
	fmt.Printf("[+] performance: memory cleared in %v\n", clearTime)

	fmt.Println("[+] encrypted data sample (first 50 bytes):")
	for i := 0; i < 50 && i < len(data.Data); i++ {
		fmt.Printf("%02x ", data.Data[i])
		if (i+1)%16 == 0 {
			fmt.Println()
		}
	}
	fmt.Println()
}
