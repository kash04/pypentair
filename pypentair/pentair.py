"""Pentair account."""

from __future__ import annotations

import logging
import time
from json import dumps as json_dumps
from typing import Any, Final
from urllib.parse import urljoin

import jwt
import requests
from boto3 import client as boto_client
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
from pycognito import Cognito

from .const import CLIENT_ID, IDENTITY_POOL_ID, REGION_NAME, USER_POOL_ID
from .exceptions import PentairApiException, PentairAuthenticationError
from .utils import decode, redact

_LOGGER = logging.getLogger(__name__)

BASE_URL: Final = "https://api.pentair.cloud/"
TOKEN_REFRESH_WINDOW: Final = 300  # seconds


class Pentair:
    """Pentair account."""

    _user: Cognito | None = None
    _auth: SigV4Auth | None = None

    def __init__(
        self,
        *,
        username: str | None = None,
        access_token: str | None = None,
        id_token: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        """Initialize."""
        self._username = username
        self._access_token = access_token
        self._id_token = id_token
        self._refresh_token = refresh_token

    @property
    def access_token(self) -> str | None:
        """Return the access token."""
        return self._user.access_token if self._user else self._access_token

    @property
    def id_token(self) -> str | None:
        """Return the id token."""
        return self._user.id_token if self._user else self._id_token

    @property
    def refresh_token(self) -> str | None:
        """Return the refresh token."""
        return self._user.refresh_token if self._user else self._refresh_token

    def get_user(self) -> Cognito:
        """Return the Cognito user."""
        if self._user is None:
            self._user = Cognito(
                decode(USER_POOL_ID),
                decode(CLIENT_ID),
                username=self._username,
                access_token=self.access_token,
                id_token=self.id_token,
                refresh_token=self.refresh_token,
            )
            if self.access_token or self.id_token:
                try:
                    self._user.check_token()
                    self._user.verify_tokens()
                except ClientError as err:
                    _LOGGER.error(err)
                    raise PentairAuthenticationError(err) from err
        return self._user

    def get_auth(self) -> SigV4Auth:
        """Return the SigV4Auth."""
        if self.get_user().check_token() or self._auth is None:
            client = boto_client("cognito-identity", region_name=REGION_NAME)
            logins = {
                f"cognito-idp.{REGION_NAME}.amazonaws.com/{decode(USER_POOL_ID)}": self.id_token
            }
            response = client.get_id(
                IdentityPoolId=decode(IDENTITY_POOL_ID), Logins=logins
            )
            response = client.get_credentials_for_identity(
                IdentityId=response["IdentityId"], Logins=logins
            )
            credentials = Credentials(
                response["Credentials"]["AccessKeyId"],
                response["Credentials"]["SecretKey"],
                response["Credentials"]["SessionToken"],
            )
            self._auth = SigV4Auth(credentials, "execute-api", REGION_NAME)
        return self._auth

    def get_tokens(self) -> dict[str, str]:
        """Return the tokens."""
        if (user := self.get_user()).access_token:
            return {
                "access_token": user.access_token,
                "id_token": user.id_token,
                "refresh_token": user.refresh_token,
            }
        return {}

    def authenticate(self, password: str) -> None:
        """Authenticate a user."""
        try:
            self.get_user().authenticate(password=password)
        except ClientError as err:
            _LOGGER.error(err)
            raise PentairAuthenticationError(err) from err

    def logout(self) -> None:
        """Logout of all clients (including app)."""
        self.get_user().logout()

    def get_device(self, device_id: str) -> Any:
        """Get device."""
        return self.__get(f"device/device-service/user/device/{device_id}")

    def get_devices(self) -> Any:
        """Get devices."""
        return self.__get("device/device-service/user/devices")

    def update_device(self, device_id: str, fields: dict[str, Any]) -> Any:
        """Update device fields."""
        return self.__put(
            f"device/device-service/user/device/{device_id}",
            json={"payload": fields},
            success_code="set_device_success",
        )

    def refresh_tokens(self) -> None:
        """Renew the Cognito tokens and drop the cached SigV4 credentials."""
        self.get_user().renew_access_token()
        self._auth = None

    def _id_token_expires_in(self) -> float:
        """Return the seconds until the id token expires, or 0 if unknown."""
        if not (token := self.id_token):
            return 0
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            return float(claims["exp"]) - time.time()
        except (jwt.PyJWTError, KeyError, TypeError, ValueError):
            return 0

    def __send(
        self, method: str, url: str, data: bytes | None, **kwargs: Any
    ) -> requests.Response:
        """Sign and send a request."""
        headers = {"x-amz-id-token": self.id_token}
        if data is not None:
            headers["content-type"] = "application/json; charset=UTF-8"
        # The body must be attached before signing, as it is part of the signature.
        request = AWSRequest(
            method=method, url=urljoin(BASE_URL, url), data=data, headers=headers
        )
        self.get_auth().add_auth(request)
        prepped = request.prepare()
        return requests.request(
            method,
            prepped.url,
            headers=prepped.headers,
            data=data,
            timeout=10,
            **kwargs,
        )

    def __request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        success_code: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Make a request."""
        _LOGGER.debug(
            "Making %s request to %s with %s", method, url, redact(json or kwargs)
        )

        if self.refresh_token and self._id_token_expires_in() < TOKEN_REFRESH_WINDOW:
            self.refresh_tokens()

        data = None if json is None else json_dumps(json).encode()
        response = self.__send(method, url, data, **kwargs)
        if response.status_code in (401, 403) and self.refresh_token:
            _LOGGER.debug("Received %s, refreshing tokens", response.status_code)
            self.refresh_tokens()
            response = self.__send(method, url, data, **kwargs)

        json = response.json()
        _LOGGER.debug(
            "Received %s response from %s: %s", response.status_code, url, redact(json)
        )
        if (status_code := response.status_code) != 200:
            _LOGGER.error("Status: %s - %s", status_code, json)
            response.raise_for_status()
        if success_code and (json.get("data") or {}).get("code") != success_code:
            _LOGGER.error("Unexpected response from %s: %s", url, json)
            raise PentairApiException(f"Unexpected response: {json}")
        return json

    def __get(self, url: str, **kwargs: Any) -> Any:
        """Make a get request."""
        return self.__request("get", url, **kwargs)

    def __post(  # pylint: disable=unused-private-member
        self, url: str, **kwargs: Any
    ) -> Any:
        """Make a post request."""
        return self.__request("post", url, **kwargs)

    def __put(self, url: str, **kwargs: Any) -> Any:
        """Make a put request."""
        return self.__request("put", url, **kwargs)
