import pyotp

def generate_totp(totp_secret: str, issuer = None) -> str:
    return pyotp.TOTP(totp_secret, issuer=issuer).now()
