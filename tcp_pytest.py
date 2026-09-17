import pytest

from tcp_validation import(
    PortRangeValidationError,
    validate_port_range
)

@pytest.mark.parametrize(
    "start_port, end_port",
    [
        (1, 1),
        (1, 65535),
        (80, 500),
        (443, 443),
        (65535, 65535),
    ],
)
def test_valid_port_ranges(start_port, end_port):
    assert validate_port_range(start_port, end_port) == None

@pytest.mark.parametrize(
    "start_port, end_port",
    [
        (0, 1),
        (-1, 1),
        (80, 1000000),
        (65536, 65536),
        (420, 69),
    ],
)
def test_invalid_port_ranges(start_port, end_port):
    with pytest.raises(PortRangeValidationError):
        validate_port_range(start_port, end_port) 

@pytest.mark.parametrize(
    "start_port, end_port",
    [
        ("400", 1000),
        (1, "beans"),
        (80.0, 60000),
        (True, 65535),
        (None, 69),
    ],
)
def test_invalid_port_typing(start_port, end_port):
    with pytest.raises(PortRangeValidationError):
        validate_port_range(start_port, end_port)