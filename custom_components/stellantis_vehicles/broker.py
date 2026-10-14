"""Broker mode: read the vehicle from an MQTT broker fed by a poller, not from Stellantis.

A separate poller (one client on the Stellantis account, with its own login,
OTP pairing, retries and back-off) publishes the API's answers, unchanged, as
retained messages, and runs the remote commands it receives:

  <prefix>/raw/vehicles     GET /connectedcar/v4/user/vehicles
  <prefix>/raw/status       GET .../vehicles/{id}/status
  <prefix>/raw/last_trip    a trips page holding the newest trip
  <prefix>/raw/rights       GET /applications/cvs/v4/rights/vehicle/{vin}
  <prefix>/raw/maintenance  the vehicle's maintenance link (absent if unsupported)
  <prefix>/request/<user>   commands: {"id", "service", "params"} (written here)
  <prefix>/response/<user>  the car's replies as Stellantis sends them, with
                            correlation_id = the request id (read here)

So this integration keeps all its entities and logic and only swaps its two
transports: HTTP GETs to Stellantis become reads of the retained raw topics,
and commands go to the poller instead of Stellantis' own MQTT. No account
login, no OTP, no tokens here; the broker is reached with TLS and, normally,
a client certificate whose CN is <user>.
"""

import asyncio
import json
import logging
import ssl
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import paho.mqtt.client as mqtt

from .const import (
    FIELD_BROKER_HOST,
    FIELD_BROKER_PORT,
    FIELD_BROKER_PREFIX,
    FIELD_BROKER_USER,
    FIELD_BROKER_CA_FILE,
    FIELD_BROKER_CERT_FILE,
    FIELD_BROKER_KEY_FILE,
    FIELD_BROKER_PASSWORD,
    FIELD_BROKER_TLS,
    MQTT_RESP_TOPIC,
)
from .exceptions import CommunicationError
from .stellantis import MqttClientMod, StellantisVehicles
from .utils import get_datetime

_LOGGER = logging.getLogger(__name__)

STELLANTIS_HOSTS = ("api.groupe-psa.com",)
RAW_WAIT_S = 20         # first retained messages after (re)connecting
KEEPALIVE_S = 60


def raw_name_for(url: str) -> str | None:
    """Which raw topic answers a Stellantis GET (None: not a Stellantis API call)."""
    parsed = urlparse(url)
    if parsed.hostname not in STELLANTIS_HOSTS:
        return None
    path = parsed.path.rstrip("/")
    if "/rights/vehicle/" in path:
        return "rights"
    if path.endswith("/status"):
        return "status"
    if path.endswith("/trips"):
        return "last_trip"
    if "/maintenance" in path:
        return "maintenance"
    if path.endswith("/user/vehicles"):
        return "vehicles"
    return "unsupported"


class StellantisBrokerVehicles(StellantisVehicles):
    """StellantisVehicles with the poller's broker as its only transport."""

    def __init__(self, hass) -> None:
        super().__init__(hass)
        self._raw: dict[str, Any] = {}
        self._raw_at: dict[str, float] = {}

    # ─── Settings ──────────────────────────────────────────────────
    @property
    def _prefix(self) -> str:
        return (self.get_config(FIELD_BROKER_PREFIX) or "peugeot-e208").strip("/")

    @property
    def _user(self) -> str:
        return self.get_config(FIELD_BROKER_USER)

    @property
    def remote_commands(self):
        # The poller decides (per-user allowlist); here they are always offered.
        return True

    def disable_remote_commands(self):
        _LOGGER.debug("Broker mode: remote commands stay enabled, the poller enforces its allowlist")

    # ─── No account, no tokens ─────────────────────────────────────
    async def scheduled_tokens_refresh(self):
        return None

    async def scheduled_oauth_token_refresh(self, now=None) -> None:
        return None

    async def scheduled_mqtt_token_refresh(self, now=None, force: bool = False) -> None:
        return None

    async def refresh_oauth_token_request(self) -> None:
        return None

    async def refresh_mqtt_token_request(self, access_token_only: bool = False) -> None:
        return None

    # ─── HTTP -> retained raw topics ───────────────────────────────
    async def make_http_request(self, url, method='GET', headers=None, params=None, json_data=None, data=None,
                                timeout=60, _retried=False):
        name = raw_name_for(url)
        if name is None:
            # Not Stellantis (ABRP, vehicle pictures...): a normal request.
            return await super().make_http_request(url, method, headers, params, json_data, data, timeout, _retried)
        if method != "GET" or name == "unsupported":
            raise CommunicationError(f"Broker mode: {method} {urlparse(url).path} is not available")
        await self.connect_mqtt()
        deadline = time.monotonic() + RAW_WAIT_S
        while name not in self._raw and time.monotonic() < deadline:
            await asyncio.sleep(0.5)
        if name in self._raw:
            return self._raw[name]
        if name == "maintenance":
            return {}      # the poller publishes it only when the car has it, as Stellantis' 404
        if name == "status":
            _LOGGER.warning("Broker mode: no %s/raw/status yet", self._prefix)
            return {}      # treated like an empty status: the last values are kept
        raise CommunicationError(f"Broker mode: nothing on {self._prefix}/raw/{name} (is the poller running?)")

    # ─── The broker connection ─────────────────────────────────────
    def _ssl_context(self) -> ssl.SSLContext | None:
        """Blocking (reads files): call from the executor."""
        ca, cert, key = (self.get_config(k) for k in (FIELD_BROKER_CA_FILE, FIELD_BROKER_CERT_FILE, FIELD_BROKER_KEY_FILE))
        ctx = ssl.create_default_context(cafile=ca or None)
        if cert:
            ctx.load_cert_chain(cert, key or None)
        return ctx

    async def _connect_mqtt(self, force: bool):
        async with self._mqtt_lock:
            if self._shutting_down:
                return False
            if not force and self._mqtt is not None and self._mqtt.is_connected():
                return True
            await self._disconnect_mqtt_locked()

            client = MqttClientMod(client_id=f"stellantis-ha-{self._user}-{uuid4().hex[:6]}",
                                   clean_session=True, protocol=mqtt.MQTTv311)
            if self.get_config(FIELD_BROKER_TLS) is not False:
                client.tls_set_context(await self._hass.async_add_executor_job(self._ssl_context))
            else:
                _LOGGER.warning("Broker mode: TLS is off; only for a broker on a private network")
            if self.get_config(FIELD_BROKER_PASSWORD):
                client.username_pw_set(self._user, self.get_config(FIELD_BROKER_PASSWORD))
            client.on_connect = self._on_mqtt_connect
            client.on_disconnect = self._on_mqtt_disconnect
            client.on_message = self._on_mqtt_message
            client.on_subscribe = self._on_mqtt_subscribe
            client.reconnect_delay_set(min_delay=5, max_delay=300)
            self._mqtt = client
            try:
                await self._hass.async_add_executor_job(
                    client.connect, self.get_config(FIELD_BROKER_HOST), int(self.get_config(FIELD_BROKER_PORT) or 8883),
                    KEEPALIVE_S)
                client.loop_start()
            except Exception as e:
                _LOGGER.warning("Broker mode: cannot connect to %s: %s", self.get_config(FIELD_BROKER_HOST), e)
                # loop_start anyway: paho keeps retrying in the background.
                client.loop_start()
            return client.is_connected()

    def _on_mqtt_connect(self, client, userdata, flags, result_code) -> None:
        if result_code != 0:
            _LOGGER.warning("Broker mode: connection refused (%s)", mqtt.connack_string(result_code))
            return
        self._mqtt_connected = True
        self._hass.loop.call_soon_threadsafe(self._update_all_listeners)
        self._mqtt_subscriptions.clear()
        for topic in (f"{self._prefix}/raw/#", f"{self._prefix}/response/{self._user}"):
            result, mid = client.subscribe(topic, qos=1)
            if result == mqtt.MQTT_ERR_SUCCESS:
                self._mqtt_subscriptions[mid] = topic
        _LOGGER.debug("Broker mode: connected, subscribed to %s/raw/# and response/%s", self._prefix, self._user)

    def _on_mqtt_disconnect(self, client, userdata, result_code):
        _LOGGER.debug("Broker mode: disconnected (%s), paho reconnects", mqtt.error_string(result_code))
        self._mqtt_connected = False
        self._hass.loop.call_soon_threadsafe(self._update_all_listeners)

    def _on_mqtt_message(self, client, userdata, msg) -> None:
        try:
            if msg.topic.startswith(f"{self._prefix}/raw/"):
                self._raw[msg.topic.rsplit("/", 1)[1]] = json.loads(msg.payload)
                self._raw_at[msg.topic] = time.time()
                return
            data = json.loads(msg.payload)
            if "correlation_id" in data and ("return_code" in data or "process_code" in data):
                # A Stellantis reply relayed by the poller: the stock handler takes it
                # from here (command history, refresh after "0", notifications).
                super()._on_mqtt_message(client, userdata, SimpleNamespace(
                    topic=MQTT_RESP_TOPIC + "broker", payload=msg.payload, qos=msg.qos))
            elif data.get("state") in ("rejected", "failed"):
                _LOGGER.warning("Broker mode: command %s %s: %s", data.get("action"), data.get("state"),
                                data.get("message"))
            else:
                _LOGGER.debug("Broker mode: command %s %s: %s", data.get("action"), data.get("state"),
                              data.get("message"))
        except Exception:
            _LOGGER.exception("Broker mode: error handling a message on %s", msg.topic)

    # ─── Commands -> the poller ────────────────────────────────────
    async def send_mqtt_message(self, service, message, vehicle, force_token_refresh=False, action_id=None):
        if self._mqtt is None or not self._mqtt.is_connected():
            await self.connect_mqtt()
        if self._mqtt is None or not self._mqtt.is_connected():
            raise CommunicationError("Broker mode: not connected to the broker, cannot send the command")
        if action_id is None:
            action_id = uuid4().hex + get_datetime().strftime("%Y%m%d%H%M%S%f")[:-3]
        body = json.dumps({"id": action_id, "service": service, "params": message})
        info = self._mqtt.publish(f"{self._prefix}/request/{self._user}", body, qos=1, retain=False)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            _LOGGER.warning("Broker mode: failed to send the command: %s", mqtt.error_string(info.rc))
            return None
        return action_id
