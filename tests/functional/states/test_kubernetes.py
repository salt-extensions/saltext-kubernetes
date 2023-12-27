import pytest

pytestmark = [
    pytest.mark.requires_salt_states("kubernetes.exampled"),
]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


def test_replace_this_this_with_something_meaningful(kubernetes):
    echo_str = "Echoed!"
    ret = kubernetes.exampled(echo_str)
    assert ret.result
    assert not ret.changes
    assert echo_str in ret.comment
