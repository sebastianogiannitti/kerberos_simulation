# Kerberos Protocol Simulation

La simulazione si concentra nel mostrare la gestione dei ticket del protocollo.

Per la descrizione, consultare [Presentazione](./Presentazione.pdf).

## Requisiti

Per eseguire il progetto è necessario installare le dipendenze Python elencate in `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Struttura del progetto

- `authentication_server.py` — Authentication Server  
- `ticket_granting_server.py` — Ticket Granting Server  
- `service_server.py` — Service Server  
- `client.py` — Client
- `client_session.py` — Sessione del Client
- `common/` — Moduli comuni (gestione chiavi, utility, ticket)  
- `main.py` — Script di avvio e testing multi-client 

## Funzionalità principali

- Gestione completa del protocollo Kerberos in Python
- Uso della crittografia simmetrica AES in modalità ECB
- Ticket con timestamp e lifetime variabile casuale
- Supporto per più client e accesso a più servizi
- Gestione degli errori tramite eccezioni e messaggi esplicativi
- Simulazione di rinnovo e riutilizzo dei ticket




