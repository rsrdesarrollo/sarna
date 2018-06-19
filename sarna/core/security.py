from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2 per second"]
)
