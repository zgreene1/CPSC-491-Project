MIN_PORT = 1
MAX_PORT = 65535

class PortRangeValidationError(ValueError):
    """Should trigger when a port range is invalid."""

def validate_port_range(start_port: int, end_port: int) -> None:
    if not isinstance(start_port, int) and not isinstance (end_port, int):
        raise PortRangeValidationError(
            f"Start and end ports must be integers.\n"
        )
    if start_port < MIN_PORT or start_port > MAX_PORT:
        raise PortRangeValidationError(
            f"Start port must be between {MIN_PORT} and {MAX_PORT}.\n"
            )
    if end_port < MIN_PORT or end_port > MAX_PORT:
        raise PortRangeValidationError(
            f"End port must be between {MIN_PORT} and {MAX_PORT}.\n"
        )
    if start_port > end_port:
        raise PortRangeValidationError(
            f"Start port must be less than end port.\n"
        )