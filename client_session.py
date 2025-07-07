import random

from authentication_server import AuthenticationServer
from common.keys import tgs_keys, kv_keys
from ticket_granting_server import TicketGrantingServer
from service_server import ServiceServer
from client import Client

def run_client(client_id, client_address):

    id_tgs = random.choice(list(tgs_keys.keys()))
    service_id = random.choice(list(kv_keys.keys()))

    print(f"\nCLIENT {client_id} sceglie TGS: {id_tgs}, servizio: {service_id}")

    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()
    service_server = ServiceServer(service_id)

    client = Client(client_id, client_address)

    print(f"\n--- CLIENT {client_id} richiede autenticazione all'AS ---")
    try:
        client.authenticate_with_as(as_server, id_tgs)
    except Exception as e:
        print("Errore nell' Authentication Server:", e)
        return None

    #time.sleep(random.randint(1, 5))

    print(f"\n--- CLIENT {client_id} richiede ticket servizio al TGS ---")
    try:
        client.request_service_ticket(tgs_server, service_id, id_tgs)
    except Exception as e:
        print("Errore nel Ticket Granting Server:", e)
        return None

    #time.sleep(random.randint(1, 5))

    print(f"\n--- CLIENT {client_id} accede al ServiceServer ---")
    try:
        client.access_service(client.ticket_v, service_server)
    except Exception as e:
        print("Errore nel Service Server:", e)

    action = random.choice([0, 1])
    #time.sleep(random.randint(1, 5))

    if action == 0:
        print(f"\n--- CLIENT {client_id} accede nuovamente a '{service_id}' ---")
        try:
            client.access_service(client.ticket_v, service_server)
        except Exception as e:
            print("Errore nel secondo accesso:", e)

    elif action == 1:
        new_server_id = random.choice([s for s in kv_keys.keys() if s != service_id])
        new_server = ServiceServer(new_server_id)
        print(f"\n--- CLIENT {client_id} richiede nuovo servizio '{new_server_id}' tramite TGS '{id_tgs}' ---")

        try:
            client.request_service_ticket(tgs_server, new_server_id, id_tgs)

            print(f"\n--- CLIENT {client_id} accede al ServiceServer ---")
            client.access_service(client.ticket_v, new_server)
        except Exception as e:
            print("Errore nuovo servizio:", e)

    print(f"\n--- CLIENT {client_id} termina le richieste ---")

    return client