from authentication_server import AuthenticationServer
from ticket_granting_server import TicketGrantingServer
from common.utils import encrypt, decrypt, now
from common.keys import user_keys

def test_tgs_flow():
    # Dati client e server
    client_id = "alice"
    client_address = "192.168.1.10"
    id_tgs = "tgs1"
    idv = "v1"  # Servizio richiesto

    # 1. AS autentica il client e restituisce dati cifrati
    as_server = AuthenticationServer()
    client_timestamp = now()
    encrypted_response = as_server.authenticate(client_id, client_address, id_tgs, client_timestamp)
    print("Messaggio cifrato AS->client:", encrypted_response.hex())

    # 2. Client decripta il messaggio AS per ottenere ticket_tgs e chiave sessione kCT
    decrypted_response = decrypt(user_keys[client_id], encrypted_response)
    print("Messaggio decifrato AS->client:", decrypted_response)

    ticket_tgs_hex = decrypted_response["ticket_tgs"]
    kCT = bytes.fromhex(decrypted_response["session_key"])

    # 3. Client crea e cifra l'authenticator
    authenticator = {
        "client_id": client_id,
        "client_address": client_address,
        "timestamp": now()
    }
    encrypted_authenticator = encrypt(kCT, authenticator)
    print("Authenticator cifrato client->TGS:", encrypted_authenticator.hex())

    # 4. Il TGS gestisce la richiesta e risponde cifrato
    tgs_server = TicketGrantingServer()
    response = tgs_server.generate_service_ticket(
        idv=idv,
        id_tgs=id_tgs,
        encrypted_ticket_tgs=bytes.fromhex(ticket_tgs_hex),
        encrypted_authenticator=encrypted_authenticator
    )
    print("Risposta cifrata TGS->client:", response.hex())

    # 5. Client decifra la risposta del TGS
    decrypted_response_tgs = decrypt(kCT, response)
    print("Risposta decifrata TGS->client:", decrypted_response_tgs)

    # 6. Verifiche base (puoi aggiungerne altre)
    assert decrypted_response_tgs["idv"] == idv
    print("Test TGS passato con successo!")

if __name__ == "__main__":
    test_tgs_flow()
