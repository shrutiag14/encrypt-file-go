package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"github.com/shrutiag14/go-file-encryption/filecrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	// If not enough args, return help text

	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}
	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encrypt":
		encryptHandle()
	case "decrypt":
		decryptHandle()
	default:
		fmt.Println("Run encrypt to encrypt a file, and decrypt to decrupt")
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Simple file encrypter for your day-to-day needs.")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\tCryptoGo encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help\t\tDisplays help text")
	fmt.Println("")
}

func encryptHandle() {
	if len(os.Args) < 3 {
		println("path file missing")
		os.Exit(0)
	}
	file := os.Args[2]
	if !validateFile(file) {
		println("file not found")
		os.Exit(0)
	}
	password := getPassword()
	fmt.Println("Encrypting file...")
	filecrypt.Encrypt(file, password)
	fmt.Println("File encrypted successfully")
}

func decryptHandle() {
	if len(os.Args) < 3 {
		println("Missing the path to the file. For more information run CryptoGo help")
		os.Exit(0)
	}

	file := os.Args[2]

	if !validateFile(file) {
		panic("File not found")
	}

	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error reading password:", err)
		os.Exit(1)

	}
	fmt.Println("\nDecrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("\nFile successfully decrypted.")
}

func getPassword() []byte {
	for {
		fmt.Print("Enter password: ")
		password, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("Error reading password:", err)
			os.Exit(1)
		}
		fmt.Println()

		fmt.Print("Confirm password: ")
		confirmPassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("Error reading password:", err)
			os.Exit(1)
		}
		fmt.Println()

		if validatePassword(password, confirmPassword) {
			return password
		}
		fmt.Println("Passwords do not match, please try again.")
	}
}

func validatePassword(password []byte, confirmPassword []byte) bool {
	if !bytes.Equal(password, confirmPassword) {
		return false
	}
	return true

}

func validateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true

}
