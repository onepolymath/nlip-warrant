from nlip_warrant.encoding import b64url_encode
from nlip_warrant.keys import KeyPair, verify_signature


def test_sign_and_verify():
    kp = KeyPair.generate("x")
    sig = kp.sign(b"hello")
    assert verify_signature(kp.key_id, b"hello", sig)
    assert not verify_signature(kp.key_id, b"hellO", sig)
    assert len(kp.key_id) == 43


def test_wrong_key_and_malformed_inputs_fail_closed():
    a, b = KeyPair.generate(), KeyPair.generate()
    sig = a.sign(b"m")
    assert not verify_signature(b.key_id, b"m", sig)
    assert not verify_signature("not-base64!", b"m", sig)
    assert not verify_signature(b64url_encode(b"short"), b"m", sig)
    assert not verify_signature(a.key_id, b"m", b64url_encode(b"short"))


def test_seeded_keys_are_deterministic_and_repr_hides_secret():
    seed = bytes(32)
    assert KeyPair.from_seed(seed).key_id == KeyPair.from_seed(seed).key_id
    assert "private" not in repr(KeyPair.from_seed(seed, "n"))
