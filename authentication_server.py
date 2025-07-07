import random

from common.ticket import Ticket
from common.keys import user_keys, tgs_keys
from common.utils import encrypt, gen_key, now, random_ticket_lifetime


class AuthenticationServer:
    @staticmethod
    def authenticate(client_id, client_address, id_tgs, client_timestamp):
        # Controlla che il client sia registrato
        if client_id not in user_keys:
            raise Exception(f"Utente {client_id} non riconosciuto")

        # Recupera la session key AS - TGS
        Ktgs = tgs_keys.get(id_tgs)
        if Ktgs is None:
            raise Exception(f"TGS {id_tgs} non riconosciuto")

        # Genera la session key client-TGS
        kCT = gen_key()

        # Timestamp attuale e durata ticket
        T2 = now()
        delta_T2 = random_ticket_lifetime()

        # Crea il ticket TGS con client_address
        ticket_tgs = Ticket(
            client_id=client_id,
            service_id=id_tgs,
            session_key=kCT,
            client_address=client_address,
            issue_time=T2,
            lifetime=delta_T2
        )

        # Cifra il ticket_tgs con la session key Ktgs
        encrypted_ticket_tgs = ticket_tgs.encrypt(Ktgs)

        # Prepara il messaggio per il client da cifrare con la chiave utente
        data_for_client = {
            "session_key": kCT.hex(),
            "id_tgs": id_tgs,
            "T2": T2,
            "delta_T2": delta_T2,
            "ticket_tgs": encrypted_ticket_tgs.hex()
        }

        encrypted_data_for_client = encrypt(user_keys[client_id], data_for_client)

        return encrypted_data_for_client