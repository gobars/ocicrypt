package blockcipher

import (
	"bytes"
	"io"
	"testing"
)

func TestBlockCipherSm4CtrCreateValid(t *testing.T) {
	_, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBlockCipherSm4CtrCreateInvalid(t *testing.T) {
	_, err := NewSM4CTRLayerBlockCipher(8)
	if err == nil {
		t.Fatal("Test should have failed due to invalid cipher size")
	}
	_, err = NewSM4CTRLayerBlockCipher(255)
	if err == nil {
		t.Fatal("Test should have failed due to invalid cipher size")
	}
}

func TestBlockCipherSm4CtrEncryption(t *testing.T) {
	var (
		symKey = []byte("0123456789012345")
		opt    = LayerBlockCipherOptions{
			Private: PrivateLayerBlockCipherOptions{
				SymmetricKey: symKey,
			},
		}
		layerData = []byte("this is some data")
	)

	bc, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	layerDataReader := bytes.NewReader(layerData)
	ciphertextReader, finalizer, err := bc.Encrypt(layerDataReader, opt)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different instantiated object to indicate an invocation at a diff time
	bc2, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := make([]byte, 1024)
	encsize, err := ciphertextReader.Read(ciphertext)
	if err != io.EOF {
		t.Fatal("Expected EOF")
	}

	ciphertextTestReader := bytes.NewReader(ciphertext[:encsize])

	lbco, err := finalizer()
	if err != nil {
		t.Fatal(err)
	}

	plaintextReader, _, err := bc2.Decrypt(ciphertextTestReader, lbco)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	size, err := plaintextReader.Read(plaintext)
	if err != io.EOF {
		t.Fatal("Expected EOF")
	}

	if string(plaintext[:size]) != string(layerData) {
		t.Fatalf("expected %q, got %q", layerData, plaintext[:size])
	}
}

func TestBlockCipherSm4CtrEncryptionInvalidKey(t *testing.T) {
	var (
		symKey = []byte("0123456789012345")
		opt    = LayerBlockCipherOptions{
			Private: PrivateLayerBlockCipherOptions{
				SymmetricKey: symKey,
			},
		}
		layerData = []byte("this is some data")
	)

	bc, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	layerDataReader := bytes.NewReader(layerData)

	ciphertextReader, finalizer, err := bc.Encrypt(layerDataReader, opt)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different instantiated object to indicate an invokation at a diff time
	bc2, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := make([]byte, 1024)
	encsize, err := ciphertextReader.Read(ciphertext)
	if err != io.EOF {
		t.Fatal("Expected EOF")
	}
	ciphertextTestReader := bytes.NewReader(ciphertext[:encsize])

	lbco, err := finalizer()
	if err != nil {
		t.Fatal(err)
	}
	lbco.Private.SymmetricKey = []byte("aaa3456789012345")

	plaintextReader, _, err := bc2.Decrypt(ciphertextTestReader, lbco)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	// first time read may not hit EOF of original source
	_, _ = plaintextReader.Read(plaintext)
	// now we must have hit eof and evaluated the plaintext
	_, err = plaintextReader.Read(plaintext)
	if err == nil {
		t.Fatal("Read() should have failed due to wrong key")
	}
}

func TestBlockCipherSM4CtrEncryptionInvalidKeyLength(t *testing.T) {
	var (
		symKey = []byte("012345")
		opt    = LayerBlockCipherOptions{
			Private: PrivateLayerBlockCipherOptions{
				SymmetricKey: symKey,
			},
		}
		layerData = []byte("this is some data")
	)

	bc, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	layerDataReader := bytes.NewReader(layerData)
	_, _, err = bc.Encrypt(layerDataReader, opt)
	if err == nil {
		t.Fatal("Test should have failed due to invalid key length")
	}
}

func TestBlockCipherSM4CtrEncryptionInvalidHMAC(t *testing.T) {
	var (
		symKey = []byte("0123456789012345")
		opt    = LayerBlockCipherOptions{
			Private: PrivateLayerBlockCipherOptions{
				SymmetricKey: symKey,
			},
		}
		layerData = []byte("this is some data")
	)

	bc, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	layerDataReader := bytes.NewReader(layerData)

	ciphertextReader, finalizer, err := bc.Encrypt(layerDataReader, opt)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different instantiated object to indicate an invokation at a diff time
	bc2, err := NewSM4CTRLayerBlockCipher(128)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext := make([]byte, 1024)
	encsize, err := ciphertextReader.Read(ciphertext)
	if err != io.EOF {
		t.Fatal("Expected EOF")
	}
	ciphertextTestReader := bytes.NewReader(ciphertext[:encsize])

	lbco, err := finalizer()
	if err != nil {
		t.Fatal(err)
	}
	lbco.Public.Hmac = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	plaintextReader, _, err := bc2.Decrypt(ciphertextTestReader, lbco)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1024)
	// we will hit the error the first time
	_, err = plaintextReader.Read(plaintext)
	if err == nil || err == io.EOF {
		t.Fatal("Read() should have failed due to Invalid HMAC verification")
	}
}
