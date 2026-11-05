from pydantic import BaseModel, AwareDatetime
from enum import Enum

class EventType(str, Enum):
    LOGIN = "login"
    SUDO = "sudo"
    CRON_CREATE = "cron_create"

class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    
class SecurityEvent(BaseModel):
    event_id: str
    host: str
    timestamp: AwareDatetime 
    event_type: EventType
    username: str | None = None
    src_ip: str | None = None
    result: Outcome
    command: str | None = None
    raw: str