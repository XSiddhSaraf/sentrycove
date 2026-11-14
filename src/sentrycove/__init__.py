"""SentryCove: an open-source agent firewall and early-warning layer for web apps."""

from .alerts import Alert, AlertDispatcher, LogSink, WebhookSink
from .config import Config, load_config
from .identity import AgentIdentity
from .middleware import SentryCove

__all__ = [
    "SentryCove",
    "AgentIdentity",
    "Alert",
    "AlertDispatcher",
    "Config",
    "LogSink",
    "WebhookSink",
    "load_config",
]
__version__ = "0.1.0"
