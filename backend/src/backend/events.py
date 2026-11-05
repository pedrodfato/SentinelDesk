from pydantic import BaseModel, AwareDatetime
from enum import Enum

class EventType(str, Enum):
    LOGIN = "login"
    SUDO = "sudo"

class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    
class SecurityEvent(BaseModel):
    event_id: str
    host: str
    timestamp: AwareDatetime 
    event_type: EventType
    user: str | None = None
    src_ip: str | None = None
    result: Outcome
    command: str | None = None
    raw: str