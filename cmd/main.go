package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	
	"stackobf/obfuscator"
)

func main() {
	file, err := os.Open("input.txt")
	if err != nil {
		fmt.Printf("[-] error opening input.txt: %v\n", err)
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
	data := obfuscator.GenerateObfuscatedData(inputStrings)
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
	fmt.Printf("[+] performance: generation took %v for %d bytes\n", genTime, len(data.Data))
	
	fmt.Println("[+] demonstration of usage :3:")
	obf := obfuscator.NewObfuscator(data)
	
	fmt.Println("[+] accessing strings via stack operations:")
	accessStart := time.Now()
	fmt.Printf("[+] Get(0): %s\n", obf.Get(0))
	fmt.Printf("[+] Get(2): %s\n", obf.Get(2))
	fmt.Printf("[+] Get(1): %s\n", obf.Get(1))
	fmt.Printf("[+] Get(3): %s\n", obf.Get(3))
	fmt.Printf("[+] Get(4): %s\n", obf.Get(4))
	fmt.Printf("[+] Get(5): %s\n", obf.Get(5))	
	fmt.Printf("[+] Get(6): %s\n", obf.Get(6))
	fmt.Printf("[+] Get(7): %s\n", obf.Get(7))
	fmt.Printf("[+] Get(8): %s\n", obf.Get(8))
	fmt.Printf("[+] Get(9): %s\n", obf.Get(9))
	fmt.Printf("[+] Get(10): %s\n", obf.Get(10))
	accessTime := time.Since(accessStart)
	
	accessedCount := 11 
	fmt.Printf("[+] performance: accessed %d strings in %v (avg: %v per string)\n", 
		accessedCount, accessTime, accessTime/time.Duration(accessedCount))
	
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
