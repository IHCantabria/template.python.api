import pytest
from template.template import Template


@pytest.mark.parametrize(
    "value1, value2, expected", [(1, 1, 2), (2, 2, 4), (3, 2, 5), (4, 2, 6), (5, 7, 12)]
)
def test_sum(value1, value2, expected):
    template = Template()
    assert template.sum(value1, value2) == expected
