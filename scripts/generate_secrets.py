# Générer une clé secrète Flask sécurisée
# Cette clé sera utilisée pour signer les sessions Flask
import secrets
print(secrets.token_hex(32))

