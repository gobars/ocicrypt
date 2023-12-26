package sm4

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/gobars/ocicrypt/blockcipher"
	"github.com/gobars/ocicrypt/blockcipher/sm3"
	"github.com/gobars/ocicrypt/utils"
	"hash"
	"io"
)

// SM4CTRLayerBlockCipher implements the AES CTR stream cipher
type SM4CTRLayerBlockCipher struct {
	keylen         int // in bytes
	reader         io.Reader
	encrypt        bool
	stream         cipher.Stream
	err            error
	hmac           hash.Hash
	expHmac        []byte
	doneEncrypting bool
}

type sm4ctrcryptor struct {
	bc *SM4CTRLayerBlockCipher
}

// NewAESCTRLayerBlockCipher returns a new SM4 SIV block cipher of 256 or 512 bits
func NewSM4CTRLayerBlockCipher(bits int) (blockcipher.LayerBlockCipher, error) {
	if bits != 128 {
		return nil, errors.New("SM4 CTR bit count not supported")
	}
	return &SM4CTRLayerBlockCipher{keylen: bits / 8}, nil
}

func (r *sm4ctrcryptor) Read(p []byte) (int, error) {
	var (
		o int
	)

	if r.bc.err != nil {
		return 0, r.bc.err
	}

	o, err := utils.FillBuffer(r.bc.reader, p)
	if err != nil {
		if err == io.EOF {
			r.bc.err = err
		} else {
			return 0, err
		}
	}

	if !r.bc.encrypt {
		if _, err := r.bc.hmac.Write(p[:o]); err != nil {
			r.bc.err = fmt.Errorf("could not write to hmac: %w", err)
			return 0, r.bc.err
		}

		if r.bc.err == io.EOF {
			// Before we return EOF we let the HMAC comparison
			// provide a verdict
			if !hmac.Equal(r.bc.hmac.Sum(nil), r.bc.expHmac) {
				r.bc.err = fmt.Errorf("could not properly decrypt byte stream; exp hmac: '%x', actual hmac: '%s'", r.bc.expHmac, r.bc.hmac.Sum(nil))
				return 0, r.bc.err
			}
		}
	}

	r.bc.stream.XORKeyStream(p[:o], p[:o])

	if r.bc.encrypt {
		if _, err := r.bc.hmac.Write(p[:o]); err != nil {
			r.bc.err = fmt.Errorf("could not write to hmac: %w", err)
			return 0, r.bc.err
		}

		if r.bc.err == io.EOF {
			// Final data encrypted; Do the 'then-MAC' part
			r.bc.doneEncrypting = true
		}
	}

	return o, r.bc.err
}

// init initializes an instance
func (bc *SM4CTRLayerBlockCipher) init(encrypt bool, reader io.Reader, opts blockcipher.LayerBlockCipherOptions) (blockcipher.LayerBlockCipherOptions, error) {
	var (
		err error
	)

	key := opts.Private.SymmetricKey
	if len(key) != bc.keylen {
		return blockcipher.LayerBlockCipherOptions{}, fmt.Errorf("invalid key length of %d bytes; need %d bytes", len(key), bc.keylen)
	}

	nonce, ok := opts.GetOpt("nonce")
	if !ok {
		nonce = make([]byte, BlockSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return blockcipher.LayerBlockCipherOptions{}, fmt.Errorf("unable to generate random nonce: %w", err)
		}
	}

	block, err := NewCipher(key)
	if err != nil {
		return blockcipher.LayerBlockCipherOptions{}, fmt.Errorf("aes.NewCipher failed: %w", err)
	}

	bc.reader = reader
	bc.encrypt = encrypt
	bc.stream = cipher.NewCTR(block, nonce)
	bc.err = nil
	bc.hmac = hmac.New(sm3.New, key)
	bc.expHmac = opts.Public.Hmac
	bc.doneEncrypting = false

	if !encrypt && len(bc.expHmac) == 0 {
		return blockcipher.LayerBlockCipherOptions{}, errors.New("HMAC is not provided for decryption process")
	}

	lbco := blockcipher.LayerBlockCipherOptions{
		Private: blockcipher.PrivateLayerBlockCipherOptions{
			SymmetricKey: key,
			CipherOptions: map[string][]byte{
				"nonce": nonce,
			},
		},
	}

	return lbco, nil
}

// GenerateKey creates a synmmetric key
func (bc *SM4CTRLayerBlockCipher) GenerateKey() ([]byte, error) {
	key := make([]byte, bc.keylen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt takes in layer data and returns the ciphertext and relevant LayerBlockCipherOptions
func (bc *SM4CTRLayerBlockCipher) Encrypt(plainDataReader io.Reader, opt blockcipher.LayerBlockCipherOptions) (io.Reader, blockcipher.Finalizer, error) {
	lbco, err := bc.init(true, plainDataReader, opt)
	if err != nil {
		return nil, nil, err
	}

	finalizer := func() (blockcipher.LayerBlockCipherOptions, error) {
		if !bc.doneEncrypting {
			return blockcipher.LayerBlockCipherOptions{}, errors.New("Read()ing not complete, unable to finalize")
		}
		if lbco.Public.CipherOptions == nil {
			lbco.Public.CipherOptions = map[string][]byte{}
		}
		lbco.Public.Hmac = bc.hmac.Sum(nil)
		return lbco, nil
	}
	return &sm4ctrcryptor{bc}, finalizer, nil
}

// Decrypt takes in layer ciphertext data and returns the plaintext and relevant LayerBlockCipherOptions
func (bc *SM4CTRLayerBlockCipher) Decrypt(encDataReader io.Reader, opt blockcipher.LayerBlockCipherOptions) (io.Reader, blockcipher.LayerBlockCipherOptions, error) {
	lbco, err := bc.init(false, encDataReader, opt)
	if err != nil {
		return nil, blockcipher.LayerBlockCipherOptions{}, err
	}

	return utils.NewDelayedReader(&sm4ctrcryptor{bc}, 1024*10), lbco, nil
}
