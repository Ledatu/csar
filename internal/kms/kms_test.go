package kms

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalProvider_EncryptDecrypt(t *testing.T) {
	p, err := NewLocalProvider(map[string]string{
		"key1": "my-secret-passphrase",
	})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	plaintext := []byte("hello world secret token")
	ctx := context.Background()

	ciphertext, err := p.Encrypt(ctx, "key1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := p.Decrypt(ctx, "key1", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestLocalProvider_DifferentKeys(t *testing.T) {
	p, err := NewLocalProvider(map[string]string{
		"key1": "passphrase-one",
		"key2": "passphrase-two",
	})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte("sensitive data")

	// Encrypt with key1
	ct1, err := p.Encrypt(ctx, "key1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt key1: %v", err)
	}

	// Decrypt with key1 should work
	dec, err := p.Decrypt(ctx, "key1", ct1)
	if err != nil {
		t.Fatalf("Decrypt key1: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Error("key1 decrypt mismatch")
	}

	// Decrypt with key2 should fail (wrong key)
	_, err = p.Decrypt(ctx, "key2", ct1)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

func TestLocalProvider_UnknownKey(t *testing.T) {
	p, err := NewLocalProvider(map[string]string{"key1": "pass"})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	ctx := context.Background()

	_, err = p.Encrypt(ctx, "nonexistent", []byte("data"))
	if err == nil {
		t.Error("Encrypt with unknown key should fail")
	}

	_, err = p.Decrypt(ctx, "nonexistent", []byte("data"))
	if err == nil {
		t.Error("Decrypt with unknown key should fail")
	}
}

func TestLocalProvider_EmptyPassphrases(t *testing.T) {
	_, err := NewLocalProvider(map[string]string{})
	if err == nil {
		t.Error("NewLocalProvider with empty passphrases should fail")
	}
}

func TestLocalProvider_TamperedCiphertext(t *testing.T) {
	p, err := NewLocalProvider(map[string]string{"key1": "pass"})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	ctx := context.Background()
	ct, err := p.Encrypt(ctx, "key1", []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with ciphertext
	ct[len(ct)-1] ^= 0xFF

	_, err = p.Decrypt(ctx, "key1", ct)
	if err == nil {
		t.Error("Decrypt of tampered ciphertext should fail")
	}
}

func TestLocalProvider_ShortCiphertext(t *testing.T) {
	p, err := NewLocalProvider(map[string]string{"key1": "pass"})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	_, err = p.Decrypt(context.Background(), "key1", []byte{1, 2, 3})
	if err == nil {
		t.Error("Decrypt of short ciphertext should fail")
	}
}

func TestLocalProvider_EmptyPlaintext(t *testing.T) {
	p, err := NewLocalProvider(map[string]string{"key1": "pass"})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	ctx := context.Background()
	ct, err := p.Encrypt(ctx, "key1", []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	dec, err := p.Decrypt(ctx, "key1", ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(dec) != 0 {
		t.Errorf("decrypted empty = %v, want empty", dec)
	}
}

// --- CachingProvider tests ---

type countingProvider struct {
	encryptCount atomic.Int64
	decryptCount atomic.Int64
	inner        Provider
}

func (c *countingProvider) Name() string                    { return "counting(" + c.inner.Name() + ")" }
func (c *countingProvider) Health(ctx context.Context) error { return c.inner.Health(ctx) }

func (c *countingProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	c.encryptCount.Add(1)
	return c.inner.Encrypt(ctx, keyID, plaintext)
}

func (c *countingProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	c.decryptCount.Add(1)
	return c.inner.Decrypt(ctx, keyID, ciphertext)
}

func (c *countingProvider) Close() error {
	return c.inner.Close()
}

func TestCachingProvider_CachesDecrypt(t *testing.T) {
	local, _ := NewLocalProvider(map[string]string{"k": "pass"})
	counter := &countingProvider{inner: local}
	cached := NewCachingProvider(counter, 5*time.Second, 0)

	ctx := context.Background()
	ct, _ := local.Encrypt(ctx, "k", []byte("my-token"))

	// First decrypt: cache miss
	dec1, err := cached.Decrypt(ctx, "k", ct)
	if err != nil {
		t.Fatalf("Decrypt 1: %v", err)
	}

	// Second decrypt: cache hit
	dec2, err := cached.Decrypt(ctx, "k", ct)
	if err != nil {
		t.Fatalf("Decrypt 2: %v", err)
	}

	if !bytes.Equal(dec1, dec2) {
		t.Error("cached results differ")
	}

	if counter.decryptCount.Load() != 1 {
		t.Errorf("decryptCount = %d, want 1 (cache should prevent second call)", counter.decryptCount.Load())
	}
}

func TestCachingProvider_TTLExpiry(t *testing.T) {
	local, _ := NewLocalProvider(map[string]string{"k": "pass"})
	counter := &countingProvider{inner: local}
	cached := NewCachingProvider(counter, 50*time.Millisecond, 0)

	ctx := context.Background()
	ct, _ := local.Encrypt(ctx, "k", []byte("token"))

	cached.Decrypt(ctx, "k", ct) //nolint: errcheck
	time.Sleep(100 * time.Millisecond)
	cached.Decrypt(ctx, "k", ct) //nolint: errcheck

	if counter.decryptCount.Load() != 2 {
		t.Errorf("decryptCount = %d, want 2 (TTL should have expired)", counter.decryptCount.Load())
	}
}

func TestCachingProvider_Singleflight(t *testing.T) {
	// Slow provider to test singleflight dedup
	local, _ := NewLocalProvider(map[string]string{"k": "pass"})
	slow := &slowProvider{inner: local, delay: 100 * time.Millisecond}
	counter := &countingProvider{inner: slow}
	cached := NewCachingProvider(counter, 5*time.Second, 0)

	ctx := context.Background()
	ct, _ := local.Encrypt(ctx, "k", []byte("token"))

	// Fire 10 concurrent decrypts
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cached.Decrypt(ctx, "k", ct) //nolint: errcheck
		}()
	}
	wg.Wait()

	// Singleflight should collapse all 10 into 1 call
	if counter.decryptCount.Load() != 1 {
		t.Errorf("decryptCount = %d, want 1 (singleflight should dedup)", counter.decryptCount.Load())
	}
}

func TestCachingProvider_InvalidateAll(t *testing.T) {
	local, _ := NewLocalProvider(map[string]string{"k": "pass"})
	counter := &countingProvider{inner: local}
	cached := NewCachingProvider(counter, 5*time.Second, 0)

	ctx := context.Background()
	ct, _ := local.Encrypt(ctx, "k", []byte("token"))

	cached.Decrypt(ctx, "k", ct) //nolint: errcheck
	cached.InvalidateAll()
	cached.Decrypt(ctx, "k", ct) //nolint: errcheck

	if counter.decryptCount.Load() != 2 {
		t.Errorf("decryptCount = %d, want 2 (cache was invalidated)", counter.decryptCount.Load())
	}
}

func TestCachingProvider_EncryptNotCached(t *testing.T) {
	local, _ := NewLocalProvider(map[string]string{"k": "pass"})
	counter := &countingProvider{inner: local}
	cached := NewCachingProvider(counter, 5*time.Second, 0)

	ctx := context.Background()
	cached.Encrypt(ctx, "k", []byte("a")) //nolint: errcheck
	cached.Encrypt(ctx, "k", []byte("b")) //nolint: errcheck

	if counter.encryptCount.Load() != 2 {
		t.Errorf("encryptCount = %d, want 2 (encrypt should not be cached)", counter.encryptCount.Load())
	}
}

type slowProvider struct {
	inner Provider
	delay time.Duration
}

func (s *slowProvider) Name() string                    { return "slow(" + s.inner.Name() + ")" }
func (s *slowProvider) Health(ctx context.Context) error { return s.inner.Health(ctx) }

func (s *slowProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	time.Sleep(s.delay)
	return s.inner.Encrypt(ctx, keyID, plaintext)
}

func (s *slowProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	time.Sleep(s.delay)
	return s.inner.Decrypt(ctx, keyID, ciphertext)
}

func (s *slowProvider) Close() error {
	return s.inner.Close()
}
