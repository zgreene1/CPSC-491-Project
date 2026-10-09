MIN_PORT = 1
MAX_PORT = 65535


class PortRangeValidationError(ValueError):
    """Raised when a TCP port range is invalid."""


def validate_port_range(start_port: int, end_port: int) -> None:
    # bool is a subclass of int, so isinstance(value, int) alone is not enough.
    # Check both endpoints before any numeric comparisons can raise TypeError.
    if type(start_port) is not int or type(end_port) is not int:
        raise PortRangeValidationError(
            "Start and end ports must be integers."
        )

    if not MIN_PORT <= start_port <= MAX_PORT:
        raise PortRangeValidationError(
            f"Start port must be between {MIN_PORT} and {MAX_PORT}."
        )
    if not MIN_PORT <= end_port <= MAX_PORT:
        raise PortRangeValidationError(
            f"End port must be between {MIN_PORT} and {MAX_PORT}."
        )
    if start_port > end_port:
        raise PortRangeValidationError(
            "Start port must not be greater than end port."
        )
