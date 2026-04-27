import hashlib
import json
import os

import httpx

from utils.httpx_client import get_httpx_client
from utils.config import get_broker_totp_secret, get_broker_issuer
from utils.logging import get_logger

logger = get_logger(__name__)


def authenticate_broker(userid, broker_pin, totp_code, date_of_birth):
    """
    Authenticate with Motilal Oswal broker and return the auth token.

    If BROKER_TOTP_SECRET is configured in .env, TOTP is auto-generated
    (the totp_code argument from the form is ignored).
    Otherwise falls back to the totp_code passed in from the form.

    Args:
        userid: Client user ID
        broker_pin: Trading password (will be hashed with API key)
        totp_code: TOTP from form (ignored if BROKER_TOTP_SECRET is set)
        date_of_birth: 2FA date in format DD/MM/YYYY (e.g., "17/09/1997")

    Returns:
        Tuple of (auth_token, None, error_message)
    """
    # Motilal uses BROKER_API_SECRET as the actual API key for hashing and headers
    api_key = os.getenv("BROKER_API_SECRET")

    try:
        client = get_httpx_client()

        totp_secret = get_broker_totp_secret()
        issuer = get_broker_issuer()

        if totp_secret:
            from utils.get_totp import generate_totp
            totp_code = generate_totp(totp_secret, issuer)
            logger.info("Motilal Oswal: TOTP auto-generated from BROKER_TOTP_SECRET")
        else:
            logger.info("Motilal Oswal: using TOTP from form input (BROKER_TOTP_SECRET not set)")

        # SHA-256(password + apikey) as per Motilal Oswal API documentation
        password_hash = hashlib.sha256(f"{broker_pin}{api_key}".encode()).hexdigest()

        # Build payload
        payload = {"userid": userid, "password": password_hash, "2FA": date_of_birth}

        # Add TOTP if available
        if totp_code:
            payload["totp"] = totp_code

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MOSL/V.1.1.0",
            "ApiKey": api_key,
            "ClientLocalIp": "127.0.0.1",
            "ClientPublicIp": "127.0.0.1",
            "MacAddress": "00:00:00:00:00:00",
            "SourceId": "WEB",
            "vendorinfo": userid,
            "osname": "Windows",
            "osversion": "10.0",
            "devicemodel": "PC",
            "manufacturer": "Generic",
            "productname": "OpenAlgo",
            "productversion": "1.0.0",
            "browsername": "Chrome",
            "browserversion": "120.0",
        }

        response = client.post(
            "https://openapi.motilaloswal.com/rest/login/v3/authdirectapi",
            headers=headers,
            json=payload,
        )

        response.status = response.status_code
        data_dict = response.json()

        logger.debug(f"Motilal Oswal auth response: status={response.status_code} msg={data_dict.get('message', '')}")

        if data_dict.get("status") == "SUCCESS" and data_dict.get("AuthToken"):
            auth_token = data_dict["AuthToken"]
            logger.info("Motilal Oswal authentication successful")
            return auth_token, None, None
        else:
            error_msg = data_dict.get("message", "Authentication failed. Please try again.")
            logger.error(f"Motilal Oswal authentication failed: {error_msg}")
            return None, None, error_msg

    except Exception as e:
        logger.error(f"Motilal Oswal authentication error: {str(e)}")
        return None, None, str(e)
