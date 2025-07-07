import json
from client_session import run_client

def main():
    with open("clients.json") as f:
        clients = json.load(f)

    for c in clients:
        run_client(c["client_id"], c["client_address"])

if __name__ == "__main__":
    main()