import pytest

pytestmark = [
    pytest.mark.requires_salt_modules("kubernetes.example_function"),
]


@pytest.fixture
def kubernetes(modules):
    return modules.kubernetes


def test_replace_this_this_with_something_meaningful(kubernetes):
    echo_str = "Echoed!"
    res = kubernetes.example_function(echo_str)
    assert res == echo_str
