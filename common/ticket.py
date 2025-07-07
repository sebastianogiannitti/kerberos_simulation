from dataclasses import dataclass
from common.utils import encrypt, decrypt, now

@dataclass
class Ticket:
    client_id: str
    service_id: str
    session_key: bytes
    client_address: str
    issue_time: int = None
    lifetime: int = 300

    def __post_init__(self):
        if self.issue_time is None:
            self.issue_time = now()

    def is_valid(self):
        current_time = now()
        delta = current_time - self.issue_time
        return 0 <= delta <= self.lifetime

    def to_dict(self):
        return {
            "client_id": self.client_id,
            "service_id": self.service_id,
            "session_key": self.session_key.hex(),
            "client_address": self.client_address,
            "issue_time": self.issue_time,
            "lifetime": self.lifetime,
        }

    def encrypt(self, key):
        return encrypt(key, self.to_dict())

    @staticmethod
    def decrypt(key, encrypted_ticket):
        data = decrypt(key, encrypted_ticket)
        return Ticket.from_dict(data)

    @staticmethod
    def from_dict(data):
        session_key = bytes.fromhex(data["session_key"])
        return Ticket(
            client_id=data["client_id"],
            service_id=data["service_id"],
            session_key=session_key,
            client_address=data["client_address"],
            issue_time=data["issue_time"],
            lifetime=data.get("lifetime", 300)
        )