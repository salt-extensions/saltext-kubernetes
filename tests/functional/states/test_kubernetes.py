import pytest

pytestmark = [
    pytest.mark.requires_salt_states("kubernetes.namespace_present"),
]


@pytest.fixture
def kubernetes(states):
    return states.kubernetes


def test_replace_this_this_with_something_meaningful(kubernetes):
    assert True
