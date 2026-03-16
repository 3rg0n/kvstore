package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ecopelan/kvstore/internal/crypto"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrNotFound       = errors.New("key not found")
	ErrNotInitialized = errors.New("store not initialized: run 'kvstore init' first")
	ErrInvalidKey     = errors.New("invalid master key")
	ErrAlreadyInit    = errors.New("store already initialized")

	metaBucket  = []byte("_meta")
	appsBucket  = []byte("_apps")
	saltKey     = []byte("salt")
	verifyKey   = []byte("verify")
	modeKey     = []byte("mode")
	sealedKey   = []byte("sealed_key")
	verifyToken = []byte("kvstore-verification-token")

	ModePassword = []byte("password")
	ModeTPM      = []byte("tpm")
)

// Entry represents a stored key-value pair with timestamps.
type Entry struct {
	Value     []byte    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store is an encrypted key-value store backed by bbolt.
type Store struct {
	db  *bolt.DB
	key []byte
}

// Open opens the store at the given path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening store: %w", err)
	}
	return &Store{db: db}, nil
}

// Init initializes a new store with the given master password.
func (s *Store) Init(password []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(metaBucket); b != nil && b.Get(saltKey) != nil {
			return ErrAlreadyInit
		}

		b, err := tx.CreateBucketIfNotExists(metaBucket)
		if err != nil {
			return fmt.Errorf("creating meta bucket: %w", err)
		}

		salt, err := crypto.GenerateSalt()
		if err != nil {
			return err
		}

		key := crypto.DeriveKey(password, salt)

		encrypted, err := crypto.Encrypt(key, verifyToken)
		if err != nil {
			return fmt.Errorf("encrypting verification token: %w", err)
		}

		if err := b.Put(saltKey, salt); err != nil {
			return fmt.Errorf("storing salt: %w", err)
		}
		if err := b.Put(verifyKey, encrypted); err != nil {
			return fmt.Errorf("storing verification: %w", err)
		}

		s.key = key
		return nil
	})
}

// Unlock verifies the master password and unlocks the store for use.
func (s *Store) Unlock(password []byte) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		if b == nil {
			return ErrNotInitialized
		}

		salt := b.Get(saltKey)
		if salt == nil {
			return ErrNotInitialized
		}

		encrypted := b.Get(verifyKey)
		if encrypted == nil {
			return ErrNotInitialized
		}

		key := crypto.DeriveKey(password, salt)

		plaintext, err := crypto.Decrypt(key, encrypted)
		if err != nil {
			return ErrInvalidKey
		}

		if string(plaintext) != string(verifyToken) {
			return ErrInvalidKey
		}

		s.key = key
		return nil
	})
}

// KeySealer provides hardware-bound key sealing (TPM or Secure Enclave).
type KeySealer interface {
	TPMSeal(data []byte) ([]byte, error)
	TPMUnseal(sealed []byte) ([]byte, error)
}

// InitTPM initializes the store with a TPM-sealed random master key.
// No password is required — the key is bound to the hardware.
func (s *Store) InitTPM(sealer KeySealer) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if b := tx.Bucket(metaBucket); b != nil && b.Get(saltKey) != nil {
			return ErrAlreadyInit
		}

		b, err := tx.CreateBucketIfNotExists(metaBucket)
		if err != nil {
			return fmt.Errorf("creating meta bucket: %w", err)
		}

		// Generate a random master key (not derived from password)
		key := make([]byte, crypto.KeySize)
		salt, err := crypto.GenerateSalt()
		if err != nil {
			return err
		}
		// Use salt as the random key material for consistency with store format
		copy(key, salt)

		// Seal the key with TPM
		sealed, err := sealer.TPMSeal(key)
		if err != nil {
			return fmt.Errorf("sealing key with TPM: %w", err)
		}

		encrypted, err := crypto.Encrypt(key, verifyToken)
		if err != nil {
			return fmt.Errorf("encrypting verification token: %w", err)
		}

		if err := b.Put(saltKey, salt); err != nil {
			return fmt.Errorf("storing salt: %w", err)
		}
		if err := b.Put(verifyKey, encrypted); err != nil {
			return fmt.Errorf("storing verification: %w", err)
		}
		if err := b.Put(modeKey, ModeTPM); err != nil {
			return fmt.Errorf("storing mode: %w", err)
		}
		if err := b.Put(sealedKey, sealed); err != nil {
			return fmt.Errorf("storing sealed key: %w", err)
		}

		s.key = key
		return nil
	})
}

// UnlockTPM unlocks a TPM-initialized store by unsealing the master key.
func (s *Store) UnlockTPM(sealer KeySealer) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		if b == nil {
			return ErrNotInitialized
		}

		sealed := b.Get(sealedKey)
		if sealed == nil {
			return ErrNotInitialized
		}

		encrypted := b.Get(verifyKey)
		if encrypted == nil {
			return ErrNotInitialized
		}

		key, err := sealer.TPMUnseal(sealed)
		if err != nil {
			return fmt.Errorf("unsealing key from TPM: %w", err)
		}

		plaintext, err := crypto.Decrypt(key, encrypted)
		if err != nil {
			return ErrInvalidKey
		}

		if string(plaintext) != string(verifyToken) {
			return ErrInvalidKey
		}

		s.key = key
		return nil
	})
}

// IsTPMMode reports whether the store was initialized with TPM key sealing.
func (s *Store) IsTPMMode() bool {
	tpm := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(metaBucket); b != nil {
			if mode := b.Get(modeKey); mode != nil && string(mode) == string(ModeTPM) {
				tpm = true
			}
		}
		return nil
	})
	return tpm
}

// IsInitialized checks if the store has been initialized with a master password.
func (s *Store) IsInitialized() bool {
	initialized := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(metaBucket); b != nil && b.Get(saltKey) != nil {
			initialized = true
		}
		return nil
	})
	return initialized
}

// Set stores a key-value pair in the given namespace.
func (s *Store) Set(namespace, key string, value []byte) error {
	if s.key == nil {
		return ErrNotInitialized
	}

	now := time.Now().UTC()

	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return fmt.Errorf("creating namespace bucket: %w", err)
		}

		entry := Entry{Value: value, CreatedAt: now, UpdatedAt: now}

		// Preserve original created_at on updates
		if existing := b.Get([]byte(key)); existing != nil {
			if decrypted, err := crypto.Decrypt(s.key, existing); err == nil {
				var old Entry
				if json.Unmarshal(decrypted, &old) == nil {
					entry.CreatedAt = old.CreatedAt
				}
			}
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshaling entry: %w", err)
		}

		encrypted, err := crypto.Encrypt(s.key, data)
		if err != nil {
			return fmt.Errorf("encrypting value: %w", err)
		}

		return b.Put([]byte(key), encrypted)
	})
}

// Get retrieves a value by namespace and key.
func (s *Store) Get(namespace, key string) (*Entry, error) {
	if s.key == nil {
		return nil, ErrNotInitialized
	}

	var entry Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return ErrNotFound
		}

		data := b.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}

		decrypted, err := crypto.Decrypt(s.key, data)
		if err != nil {
			return fmt.Errorf("decrypting value: %w", err)
		}

		return json.Unmarshal(decrypted, &entry)
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// Delete removes a key from the given namespace.
func (s *Store) Delete(namespace, key string) error {
	if s.key == nil {
		return ErrNotInitialized
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return ErrNotFound
		}
		if b.Get([]byte(key)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(key))
	})
}

// List returns all keys in a namespace.
func (s *Store) List(namespace string) ([]string, error) {
	if s.key == nil {
		return nil, ErrNotInitialized
	}

	var keys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})
	return keys, err
}

// ListNamespaces returns all namespace names (excluding internal buckets).
func (s *Store) ListNamespaces() ([]string, error) {
	if s.key == nil {
		return nil, ErrNotInitialized
	}

	var namespaces []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if string(name) != string(metaBucket) && string(name) != string(appsBucket) {
				namespaces = append(namespaces, string(name))
			}
			return nil
		})
	})
	return namespaces, err
}

// PutAppRecord stores an encrypted app record by ID.
func (s *Store) PutAppRecord(id string, data []byte) error {
	if s.key == nil {
		return ErrNotInitialized
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(appsBucket)
		if err != nil {
			return fmt.Errorf("creating apps bucket: %w", err)
		}
		encrypted, err := crypto.Encrypt(s.key, data)
		if err != nil {
			return fmt.Errorf("encrypting app record: %w", err)
		}
		return b.Put([]byte(id), encrypted)
	})
}

// GetAppRecord retrieves and decrypts an app record by ID.
func (s *Store) GetAppRecord(id string) ([]byte, error) {
	if s.key == nil {
		return nil, ErrNotInitialized
	}
	var result []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(appsBucket)
		if b == nil {
			return ErrNotFound
		}
		data := b.Get([]byte(id))
		if data == nil {
			return ErrNotFound
		}
		decrypted, err := crypto.Decrypt(s.key, data)
		if err != nil {
			return fmt.Errorf("decrypting app record: %w", err)
		}
		result = decrypted
		return nil
	})
	return result, err
}

// DeleteAppRecord removes an app record by ID.
func (s *Store) DeleteAppRecord(id string) error {
	if s.key == nil {
		return ErrNotInitialized
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(appsBucket)
		if b == nil {
			return ErrNotFound
		}
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

// ListAppRecords returns all app records (decrypted) keyed by ID.
func (s *Store) ListAppRecords() (map[string][]byte, error) {
	if s.key == nil {
		return nil, ErrNotInitialized
	}
	records := make(map[string][]byte)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(appsBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			decrypted, err := crypto.Decrypt(s.key, v)
			if err != nil {
				return fmt.Errorf("decrypting app record %s: %w", k, err)
			}
			records[string(k)] = decrypted
			return nil
		})
	})
	return records, err
}

// Close closes the store.
func (s *Store) Close() error {
	return s.db.Close()
}
