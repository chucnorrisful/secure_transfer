package main

import (
	"flag"
	"fmt"
	st "secure-transfer"
)

var keyGenMode, decodeMode, verbose bool
var pkKeyDir, pubKeyPath string

func main() {
	flag.BoolVar(&keyGenMode, "g", false, "Set to generate a new Keypair if not exists.")
	flag.BoolVar(&decodeMode, "d", false, "Set to decode given file.")
	flag.BoolVar(&verbose, "v", true, "Set to enable verbose error output.")
	flag.StringVar(&pkKeyDir, "pk-key", "keys/", "Key location of private key, target for key-gen.")
	flag.StringVar(&pubKeyPath, "pub-key", "rsa.pub", "Key location of foreign public key for encoding.")
	flag.Parse()

	if keyGenMode {
		err := st.GenerateKeypairIfNotExists(pkKeyDir, verbose)
		if err != nil {
			fmt.Println("Some errs.")
		}
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("No file selected.")
		return
	}
	if len(args) > 1 {
		fmt.Println("Too many files arguments.")
		return
	}
	file := args[0]

	if decodeMode {
		err := st.DecryptFile(file, pkKeyDir, verbose)
		if err != nil {
			fmt.Println("Some errs.")
		}
	} else {
		err := st.EncryptFile(file, pubKeyPath, verbose)
		if err != nil {
			fmt.Println("Some errs.")
		}
	}
}
