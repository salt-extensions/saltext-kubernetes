import pytest

pytestmark = [
    pytest.mark.requires_salt_modules("kubernetes.example_function"),
]


def test_replace_this_this_with_something_meaningful(salt_call_cli):
    assert True
