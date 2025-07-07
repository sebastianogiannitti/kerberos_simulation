import time

from common.keys import user_keys
from common.utils import encrypt, decrypt, now

class Client:
    def __init__(self, client_id, client_address):
        self.client_id = client_id
        self.client_address = client_address
        self.last_authenticator_timestamp = None
        self.kCT = None  # session key client-TGS
        self.ticket_tgs = None
        self.kCV = None  # session key client-service
        self.ticket_v = None

    def create_authenticator(self, session_key):
        authenticator = {
            "client_id": self.client_id,
            "client_address": self.client_address,
            "timestamp": now()
        }

        self.last_authenticator_timestamp = authenticator["timestamp"]
        return encrypt(session_key, authenticator)

    def authenticate_with_as(self, as_server, id_tgs):
        encrypted_response = as_server.authenticate(self.client_id, self.client_address, id_tgs, now())
        if not encrypted_response:
            raise Exception(f"Autenticazione AS fallita per {self.client_id}")

        data_as = decrypt(user_keys[self.client_id], encrypted_response)
        self.kCT = bytes.fromhex(data_as["session_key"])
        self.ticket_tgs = bytes.fromhex(data_as["ticket_tgs"])
        print(f"Client {self.client_id} ha ricevuto session key kCT e ticket TGS.")

    def request_service_ticket(self, tgs_server, idv, id_tgs):
        encrypted_authenticator = self.create_authenticator(self.kCT)
        encrypted_response = tgs_server.generate_service_ticket(idv, id_tgs, self.ticket_tgs, encrypted_authenticator)
        if not encrypted_response:
            raise Exception(f"Richiesta TGS fallita per {self.client_id}")

        data_tgs = decrypt(self.kCT, encrypted_response)
        self.kCV = bytes.fromhex(data_tgs["session_key"])
        self.ticket_v = bytes.fromhex(data_tgs["ticket_v"])
        print(f"Client {self.client_id} ha ricevuto session key kCV e ticket servizio.")

    def access_service(self, encrypted_ticket_v, service_server):
        encrypted_authenticator = self.create_authenticator(self.kCV)

        try:
            response = service_server.process_request(encrypted_ticket_v, encrypted_authenticator)
            decrypted_response = decrypt(self.kCV, response)

            if decrypted_response.get("timestamp") == self.last_authenticator_timestamp + 1:
                print("Accesso riuscito, autenticazione confermata")
            else:
                print("Accesso negato, risposta non valida")

        except Exception as e:
            print("Accesso al servizio negato:", e)