package tunnel

import (
	"crypto/rand"
	"io"

	"github.com/flynn/noise"
)

var (
	// NoiseProtocol is the name of the noise protocol implementation.
	// This value is used as part of the prologue. If the initiator and
	// responder aren't using the  exact same string for this value,
	// then the initial noise handshake will fail
	NoiseProtocol = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
	// HandshakePattern is noise protocol handshake pattern
	HandshakePattern = noise.HandshakeXX
	// DHFunc is a function that implements Diffie-Hellman key agreement
	DHFunc = noise.DH25519
	// CipherFunc is a function that implements an AEAD symmetric cipher
	CipherFunc = noise.CipherChaChaPoly
	// HashFunc is a function that implements a cryptographic hash function
	HashFunc = noise.HashBLAKE2s
)

// NoiseOption is used to configure noise protocol settings
type NoiseOption func(*NoiseOptions)

// NoiseOptions define noise options
type NoiseOptions struct {
	HandshakePattern noise.HandshakePattern
	DHFunc           noise.DHFunc
	CipherFunc       noise.CipherFunc
	HashFunc         noise.HashFunc
	Prologue         []byte
}

// NoiseHandshakePattern sets noise handshake pattern
func NoiseHandshakePattern(hp noise.HandshakePattern) NoiseOption {
	return func(o *NoiseOptions) {
		o.HandshakePattern = hp
	}
}

// NoiseDHFunc sets noise DH function
func NoiseDHFunc(dhf noise.DHFunc) NoiseOption {
	return func(o *NoiseOptions) {
		o.DHFunc = dhf
	}
}

// NoiseCipherFunc sets noise cipher function
func NoiseCipherFunc(cf noise.CipherFunc) NoiseOption {
	return func(o *NoiseOptions) {
		o.CipherFunc = cf
	}
}

// NoiseHashFunc sets noise hashing function
func NoiseHashFunc(hf noise.HashFunc) NoiseOption {
	return func(o *NoiseOptions) {
		o.HashFunc = hf
	}
}

// NoisePrologue sets noise prologue message
func NoisePrologue(p string) NoiseOption {
	return func(o *NoiseOptions) {
		o.Prologue = []byte(p)
	}
}

// DefaultNoiseOptions returns default noise protocol options used by micro
func DefaultNoiseOptions() NoiseOptions {
	return NoiseOptions{
		HandshakePattern: HandshakePattern,
		DHFunc:           DHFunc,
		CipherFunc:       CipherFunc,
		HashFunc:         HashFunc,
		Prologue:         []byte(NoiseProtocol),
	}
}

// Noise provides noise protocol configuration
type Noise struct {
	// options contains noise options
	options NoiseOptions
	// kp is rouut key pair
	rootKP *noise.DHKey
	// csOut is used to encrypt messages
	csOut *noise.CipherState
	// csIn is used to decrypt messages
	csIn *noise.CipherState
	// hsOK flag set if handshake is complete
	hsOK bool
}

// NewNoise initializes noise protocol configuration for micro tunnel encryption and returns it
func NewNoise(opts ...NoiseOption) (*Noise, error) {
	// get default options
	options := DefaultNoiseOptions()

	// apply requested options
	for _, o := range opts {
		o(&options)
	}

	cs := noise.NewCipherSuite(options.DHFunc, options.CipherFunc, options.HashFunc)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Noise{
		options: options,
		rootKP:  &kp,
	}, nil
}

// Handshake performs noise protocol handshake
// It returns error if the noise handshake fails
func (n *Noise) Handshake(initiator bool, randomReader io.Reader) error {
	// if the handshake has completed already, return
	if n.hsOK {
		return nil
	}

	// if no random reader has been passed it, we use rand.Reader
	if randomReader == nil {
		randomReader = rand.Reader
	}

	// CipherSuite creates cipher suite used during the handshake
	CipherSuite := noise.NewCipherSuite(n.options.DHFunc, n.options.CipherFunc, n.options.HashFunc)

	config := noise.Config{
		CipherSuite: CipherSuite,
		Random:      randomReader,
		Pattern:     n.options.HandshakePattern,
		Initiator:   initiator,
		Prologue:    n.options.Prologue,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return err
	}

	var msg []byte
	var c1, c2 *noise.CipherState
	isClient := config.Initiator
	for range config.Pattern.Messages {
		if isClient {
			msg, c1, c2, err = hs.WriteMessage(nil, nil)
			if err != nil {
				return err
			}
			// TODO: pack the message here into micro message
			// and send down some communication channel
		} else {
			// TODO: receive the message from some channel
			// and try to read it using the handshake state
			_, c1, c2, err = hs.ReadMessage(nil, msg)
			if err != nil {
				return err
			}
		}
		isClient = !isClient
	}

	if config.Initiator {
		n.csOut, n.csIn = c1, c2
	} else {
		n.csOut, n.csIn = c2, c1
	}

	// mark handshake as complete
	n.hsOK = true

	return nil
}

// RootKeyPair returns a copy of noise root key pair
func (n *Noise) RootKeyPair() *noise.DHKey {
	rootKeyPair := &noise.DHKey{}
	copy(rootKeyPair.Public, n.rootKP.Public)
	return rootKeyPair
}

// HandshakeOK returns true if the noise handshake has completed successfully
func (n *Noise) HandshakeOK() bool {
	return n.hsOK
}
