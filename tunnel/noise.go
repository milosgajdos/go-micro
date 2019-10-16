package tunnel

var (
	// NoiseProtocol is the name of the noise protocol implementation.
	// This value is used as part of the prologue. If the initiator and
	// responder aren't using the  exact same string for this value,
	// then the initial noise handshake will fail
	NoiseProtocol = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
)
