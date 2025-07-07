from common.ticket import Ticket
from common.utils import decrypt, encrypt, now
from common.keys import kv_keys

class ServiceServer:
    def __init__(self, service_id):
        self.service_id = service_id
        self.key = kv_keys.get(service_id)
        if not self.key:
            raise Exception(f"Chiave per il servizio {service_id} non trovata")

    def process_request(self, encrypted_ticket_v, encrypted_authenticator):
        # Decifra il ticket servizio
        ticket_v = Ticket.from_dict(decrypt(kv_keys[self.service_id], encrypted_ticket_v))

        # Verifica validità del ticket
        if not ticket_v.is_valid():
            raise Exception("Ticket Service non valido o scaduto")

        # Decifra l'autenticatore con la session key del ticket
        kcv = ticket_v.session_key
        authenticator = decrypt(kcv, encrypted_authenticator)

        # Verifica corrispondenza client_id e client_address
        if authenticator["client_id"] != ticket_v.client_id or authenticator["client_address"] != ticket_v.client_address:
            raise Exception("Ticket Service non valido o scaduto")

        # Risposta: conferma con timestamp incrementato cifrato con kcv
        t5 = authenticator.get("timestamp")
        if t5 is None:
            raise Exception("Authenticator non contiene timestamp")

        response = encrypt(kcv, {"timestamp": t5 + 1})
        return response
