package secretservice

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewKeypair(t *testing.T) {
	group := rfc2409SecondOakleyGroup()
	private, public, err := group.NewKeypair()
	require.NoError(t, err)
	require.NotNil(t, private)
	require.NotNil(t, public)
	private2, public2, err := group.NewKeypair()
	require.NoError(t, err)
	require.NotEqual(t, private.Cmp(private2), 0, "should get different private key with every keygen")
	require.NotEqual(t, public.Cmp(public2), 0, "should get different public key with every keygen")
}

func TestKeygen(t *testing.T) {
	group := rfc2409SecondOakleyGroup()
	myPrivate, myPublic, err := group.NewKeypair()
	require.NoError(t, err)
	theirPrivate, theirPublic, err := group.NewKeypair()
	require.NoError(t, err)

	myKey, err := group.keygenHKDFSHA256AES128(theirPublic, myPrivate)
	require.NoError(t, err)
	theirKey, err := group.keygenHKDFSHA256AES128(myPublic, theirPrivate)
	require.NoError(t, err)
	require.Equal(t, myKey, theirKey)
}

func TestEncryption(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("hello world")
	iv, ciphertext, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)
	gotPlaintext, err := unauthenticatedAESCBCDecrypt(iv, ciphertext, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, gotPlaintext)
}

func TestEncryptionRng(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("hello world")
	iv1, ciphertext1, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)
	iv2, ciphertext2, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)
	require.NotEqual(t, iv1, iv2)
	require.NotEqual(t, ciphertext1, ciphertext2)
}

var pkcs7tests = []struct {
	in  []byte
	out []byte
}{
	{[]byte{}, []byte{4, 4, 4, 4}},
	{[]byte{1, 2}, []byte{1, 2, 2, 2}},
	{[]byte{1, 2, 3}, []byte{1, 2, 3, 1}},
	{[]byte{1, 2, 3, 4}, []byte{1, 2, 3, 4, 4, 4, 4, 4}},
	{[]byte{1, 2, 3, 4, 5}, []byte{1, 2, 3, 4, 5, 3, 3, 3}},
	{[]byte{1, 2, 3, 4, 1, 1, 1}, []byte{1, 2, 3, 4, 1, 1, 1, 1}},
}

func TestPKCS7(t *testing.T) {
	for _, testCase := range pkcs7tests {
		require.Equal(t, padPKCS7(testCase.in, 4), testCase.out)
		preimage, err := unpadPKCS7(testCase.out, 4)
		require.NoError(t, err)
		require.Equal(t, preimage, testCase.in)
	}

	_, err := unpadPKCS7([]byte{}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 4}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 3}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 4, 1, 1, 1, 2}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 0}, 4)
	require.EqualError(t, err, "invalid pkcs7 padding length 0")
	_, err = unpadPKCS7([]byte{1, 2, 3, 5, 5, 5, 5, 5}, 4)
	require.EqualError(t, err, "invalid pkcs7 padding length 5")
	_, err = unpadPKCS7([]byte{1}, 0)
	require.EqualError(t, err, "invalid block size 0")
	_, err = unpadPKCS7([]byte{1}, -1)
	require.EqualError(t, err, "invalid block size -1")
	_, err = unpadPKCS7([]byte{1}, 256)
	require.EqualError(t, err, "invalid block size 256")
}

// TestDecryptionErrors tests that decryption errors are properly returned
// rather than being swallowed. This validates the fix for the security issue
// where decryption failures would return (nil, nil) instead of (nil, err).
func TestDecryptionErrors(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	// Test 1: Invalid padding should return an error
	invalidIV := make([]byte, 16)
	invalidCiphertext := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	} // 16 bytes, invalid padding
	_, err := unauthenticatedAESCBCDecrypt(invalidIV, invalidCiphertext, key)
	require.Error(t, err, "decryption with invalid padding should return an error")

	// Test 2: An invalid AES key size should return an error.
	_, err = unauthenticatedAESCBCDecrypt(invalidIV, invalidCiphertext, []byte("too short"))
	require.Error(t, err, "decryption with an invalid key size should return an error")

	// Test 3: Corrupting the ciphertext should produce invalid padding.
	// The 30-byte plaintext produces two ciphertext blocks with two bytes of
	// padding. Flipping the last byte of the penultimate ciphertext block
	// deterministically flips the last padding byte from 0x02 to 0xfd.
	plaintext := []byte("0123456789abcdefsecret message")
	iv, ciphertext, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)

	corruptedCiphertext := append([]byte(nil), ciphertext...)
	corruptedCiphertext[len(corruptedCiphertext)-aes.BlockSize-1] ^= 0xFF
	_, err = unauthenticatedAESCBCDecrypt(iv, corruptedCiphertext, key)
	require.Error(t, err, "decryption of corrupted ciphertext should return an error")
}
