"""SignalMoat: an open-source agent firewall and early-warning layer for web apps."""

from .alerts import Alert, AlertDispatcher, LogSink, WebhookSink
from .config import Config, load_config
from .engine import Engine, RequestInfo, Verdict
from .identity import AgentIdentity
from .middleware import SignalMoat

__all__ = [
    "SignalMoat",
    "AgentIdentity",
    "Alert",
    "AlertDispatcher",
    "Config",
    "Engine",
    "RequestInfo",
    "Verdict",
    "LogSink",
    "WebhookSink",
    "load_config",
]
__version__ = "0.3.1"
