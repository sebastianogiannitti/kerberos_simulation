import random

from common.ticket import Ticket
from common.utils import decrypt, encrypt, gen_key, now, random_ticket_lifetime
from common.keys import tgs_keys, kv_keys

class TicketGrantingServer:
    @staticmethod
    def generate_service_ticket(idv, id_tgs, encrypted_ticket_tgs, encrypted_authenticator):

        # Recupera chiave TGS corrispondente
        key_tgs = tgs_keys.get(id_tgs)
        if not key_tgs:
            raise Exception(f"Chiave per TGS {id_tgs} non trovata!")

        # Decifra il ticket TGS
        ticket_tgs_data = decrypt(key_tgs, encrypted_ticket_tgs)
        ticket_tgs = Ticket(
            client_id=ticket_tgs_data["client_id"],
            service_id=ticket_tgs_data["service_id"],
            session_key=bytes.fromhex(ticket_tgs_data["session_key"]),
            client_address=ticket_tgs_data["client_address"],
            issue_time=ticket_tgs_data["issue_time"],
            lifetime=ticket_tgs_data["lifetime"]
        )

        # Verifica validità temporale del ticket TGS
        if not ticket_tgs.is_valid():
            raise Exception("Ticket TGS non valido o scaduto")

        # Decifra l'autenticatore con la session key kCT
        kct = ticket_tgs.session_key
        authenticator = decrypt(kct, encrypted_authenticator)

        # Verifica autenticatore (id client e address)
        if authenticator["client_id"] != ticket_tgs.client_id or authenticator["client_address"] != ticket_tgs.client_address:
            raise Exception("Authenticator non valido (ID o address errati)")


        # Genera session key client-service e ticket per il servizio
        kcv = gen_key()
        t4 = now()
        delta_t4 = random_ticket_lifetime()

        ticket_v = Ticket(
            client_id=ticket_tgs.client_id,
            service_id=idv,
            session_key=kcv,
            client_address=ticket_tgs.client_address,
            issue_time=t4,
            lifetime=delta_t4
        )

        # Recupera la chiave Kv corretta per cifrare il ticket del servizio
        key_service = kv_keys.get(idv)
        if not key_service:
            raise Exception(f"Chiave per servizio {idv} non trovata")

        encrypted_ticket_v = ticket_v.encrypt(key_service)

        # Prepara la risposta da inviare al client cifrata con kCT
        data_for_client = {
            "session_key": kcv.hex(),
            "idv": idv,
            "T4": t4,
            "delta_T4": delta_t4,
            "ticket_v": encrypted_ticket_v.hex()
        }

        encrypted_data = encrypt(kct, data_for_client)

        return encrypted_data