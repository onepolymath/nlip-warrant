import pytest

from nlip_warrant import MemoryRevocationStore, Revocation, SqliteRevocationStore

from .conftest import key

BLOCK = "ab" * 32


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        yield MemoryRevocationStore()
    else:
        s = SqliteRevocationStore(tmp_path / "rev.sqlite3")
        yield s
        s.close()


def test_publish_and_lookup(store):
    alice = key("alice")
    rev = Revocation.create(alice, BLOCK, at=10, reason="lost device")
    assert rev.signature_valid()
    assert store.publish(rev)
    assert store.publish(rev)  # idempotent
    assert store.revokers(BLOCK) == {alice.key_id}
    assert store.revokers("cd" * 32) == frozenset()


def test_badly_signed_revocations_are_dropped(store):
    alice, mallory = key("alice"), key("mallory")
    rev = Revocation.create(mallory, BLOCK, at=10).model_copy(update={"by": alice.key_id})
    assert not rev.signature_valid()
    assert not store.publish(rev)
    assert store.revokers(BLOCK) == frozenset()


def test_sqlite_store_is_durable(tmp_path):
    path = tmp_path / "rev.sqlite3"
    alice = key("alice")
    first = SqliteRevocationStore(path)
    first.publish(Revocation.create(alice, BLOCK, at=1))
    first.close()
    second = SqliteRevocationStore(path)
    assert second.revokers(BLOCK) == {alice.key_id}
    second.close()
