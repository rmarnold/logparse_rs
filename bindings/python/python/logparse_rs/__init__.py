# Expose the Rust extension at package import and keep helper module accessible
from .logparse_rs import *  # type: ignore  # noqa: F403
# make `from logparse_rs import rust_accel` work
from . import rust_accel  # noqa: F401
