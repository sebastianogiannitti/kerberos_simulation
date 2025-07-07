from common.keys import user_keys, tgs_keys
from common.utils import decrypt
from authentication_server import AuthenticationServer

# Crea istanza AS
as_server = AuthenticationServer()

# Parametri di test
client_id = "alice"
client_address = "192.168.1.10"
id_tgs = "tgs2"
client_timestamp = 1234567890  # esempio timestamp

# Chiama authenticate
encrypted_response = as_server.authenticate(client_id, client_address, id_tgs, client_timestamp)
if encrypted_response is None:
    print("Autenticazione fallita")
    exit()

# Decifra il messaggio con la chiave utente di alice
decrypted_response = decrypt(user_keys[client_id], encrypted_response)

print("Messaggio decifrato ricevuto da AS:")
print(decrypted_response)

# Ora decifra il ticket_tgs contenuto nel messaggio
ticket_tgs_hex = decrypted_response["ticket_tgs"]
ticket_tgs_bytes = bytes.fromhex(ticket_tgs_hex)

# Decrypt del ticket TGS con chiave AS-TGS
ticket_tgs_data = decrypt(tgs_keys.get(id_tgs), ticket_tgs_bytes)
print("Ticket TGS decifrato:")
print(ticket_tgs_data)
