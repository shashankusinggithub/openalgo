import json
import os

import httpx

from utils.httpx_client import get_httpx_client
from utils.get_totp import generate_totp
from utils.config import get_broker_totp_secret, get_broker_issuer
from utils.logging import get_logger

logger = get_logger(__name__)


def authenticate_broker(clientcode, broker_pin, totp_code):
    """
    Authenticate with Angel One and return the auth token.

    If BROKER_TOTP_SECRET is configured in .env, TOTP is auto-generated
    (the totp_code argument from the form is ignored).
    Otherwise falls back to the totp_code passed in from the form.
    """
    api_key = os.getenv("BROKER_API_KEY")

    try:
        client = get_httpx_client()

        totp_secret = get_broker_totp_secret()
        issuer = get_broker_issuer()

        if totp_secret:
            totp_code = generate_totp(totp_secret, issuer)
            logger.info("Angel One: TOTP auto-generated from BROKER_TOTP_SECRET")
        else:
            logger.info("Angel One: using TOTP from form input (BROKER_TOTP_SECRET not set)")

        payload = json.dumps({"clientcode": clientcode, "password": broker_pin, "totp": totp_code})
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-UserType": "USER",
            "X-SourceID": "WEB",
            "X-ClientLocalIP": "CLIENT_LOCAL_IP",
            "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
            "X-MACAddress": "MAC_ADDRESS",
            "X-PrivateKey": api_key,
        }

        response = client.post(
            "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword",
            headers=headers,
            content=payload,
        )

        # Add status attribute for compatibility with the existing codebase
        response.status = response.status_code

        data = response.text
        data_dict = json.loads(data)

        logger.debug(f"Angel One auth response: {data_dict.get('message', '')} status={response.status_code}")

        if data_dict.get("data") and "jwtToken" in data_dict["data"]:
            auth_token = data_dict["data"]["jwtToken"]
            feed_token = data_dict["data"].get("feedToken", None)
            logger.info("Angel One authentication successful")
            return auth_token, feed_token, None
        else:
            error_msg = data_dict.get("message", "Authentication failed. Please try again.")
            logger.error(f"Angel One authentication failed: {error_msg}")
            return None, None, error_msg

    except Exception as e:
        logger.error(f"Angel One authentication error: {str(e)}")
        return None, None, str(e)
