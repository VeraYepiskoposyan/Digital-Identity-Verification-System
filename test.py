from sign import sign_credential
from verify import verify_credential

credential = {
    "name": "Vera Yepiskoposyan",
    "passport_id": "AM123456",
    "expiry": "2030-01-01"
}

signature = sign_credential(credential)

print("Signature created!")

is_valid = verify_credential(credential, signature)

print("Valid:", is_valid)