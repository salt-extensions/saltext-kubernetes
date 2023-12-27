import pytest

pytestmark = [
    pytest.mark.requires_salt_modules("kubernetes.ping"),
]


@pytest.fixture
def kubernetes(modules):
    return modules.kubernetes


def test_replace_this_this_with_something_meaningful(kubernetes):
    assert True
