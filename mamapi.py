from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from collections.abc import MutableMapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import FrameType
from typing import Any, Self

import apprise  # type: ignore
import requests  # type: ignore

logger = logging.getLogger(__name__)
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="[%Y-%m-%d %H:%M:%S]"
)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)  # intended to handle DEBUG and INFO
stdout_handler.setFormatter(formatter)
stdout_handler.addFilter(lambda record: record.levelno < logging.WARNING)
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.WARNING)  # intended to handle WARNING, ERROR, CRITICAL
stderr_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)
logger.addHandler(stderr_handler)


class SleepInterruptException(Exception):
    pass


class StateSingleton:
    _instance = None

    def __new__(cls) -> Self:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        # Avoid reinitialization if already constructed
        if not hasattr(self, "_initialized"):
            self.last_update_ip: str | None = None
            self.last_update_asn: str | None = None
            self.last_update_mamid: str | None = None
            self.last_update_time: datetime | None = None
            self.ip: str | None = None
            self.asn: str | None = None
            self.mismatched_asn: bool = False
            self._initialized: bool = True

    def to_dict(self) -> MutableMapping[str, Any]:
        return {
            "last_update_ip": self.last_update_ip,
            "last_update_asn": self.last_update_asn,
            "last_update_mamid": self.last_update_mamid,
            "last_update_time": self.last_update_time,
        }

    def load(self, data: MutableMapping[str, Any]) -> None:
        self.last_update_ip = data.get("last_update_ip")
        self.last_update_asn = data.get("last_update_asn")
        self.last_update_mamid = data.get("last_update_mamid")
        provided_last_update_time = data.get("last_update_time")
        if provided_last_update_time:
            provided_last_update_time = datetime.fromtimestamp(
                provided_last_update_time, UTC
            )
            self.last_update_time = provided_last_update_time

    def refresh(
        self, latest_ip: str | None = None, latest_asn: str | None = None
    ) -> None:
        if not latest_ip or not latest_asn:
            latest_ip, latest_asn = return_identity()
        if not latest_ip:
            logger.error("Failed to grab external IP/ASN - no internet")
            if env_shutdown_on_disconnect:
                close_script("SHUTDOWN_ON_DISCONNECT is truthy", 0)
            logger.error("Checking for internet every 5 minutes")
            interruptable_sleep(300)
            while True:
                latest_ip, latest_asn = return_identity()
                if latest_ip:
                    break
                interruptable_sleep(300)
            logger.info(
                f"Connection restored. External IP: {latest_ip} ASN: {latest_asn}"
            )
        logger.debug(f"Fetched external IP: {latest_ip} and external ASN {latest_asn}")
        if self.ip != latest_ip:
            if (latest_ip != self.last_update_ip) and self.last_update_ip:
                logger.info("Detected IP change from last MAM session update")
                logger.info(f"Last MAM session IP: {self.last_update_ip}")
                logger.info(f"Current IP: {latest_ip}")
                logger.info(f"Current ASN: {latest_asn}")
            elif state.mismatched_asn:
                logger.info("Detected IP change:")
                logger.info(f"Current IP: {latest_ip}")
                logger.info(f"Current ASN: {latest_asn}")
            self.ip = latest_ip
            self.asn = latest_asn

    def mam_ip_updated(self, mamid: str, update_time: bool) -> None:
        self.last_update_ip = self.ip
        self.last_update_mamid = mamid
        if update_time:
            self.last_update_time = timeNow()
        if self.asn:
            self.last_update_asn = self.asn
        else:
            self.last_update_asn = None
        self.mismatched_asn = False
        saveData()

    @property
    def ratelimited(self) -> float | None:
        if not self.last_update_time:
            return None
        seconds_remaining = (
            timedelta(minutes=61) - (timeNow() - self.last_update_time)
        ).total_seconds()
        return max(seconds_remaining, 0.0)


class Session:
    def __init__(
        self,
        mam_id: str,
        last_update_ip: str | None = None,
    ) -> None:
        self.mam_id: str = mam_id
        self.last_update_ip: str | None = last_update_ip

    @classmethod
    def from_dict(cls, data: MutableMapping[str, Any]) -> Self:
        return cls(
            mam_id=data["mam_id"],
            last_update_ip=data["last_update_ip"],
        )

    def to_dict(self) -> MutableMapping[str, Any]:
        return {
            "mam_id": self.mam_id,
            "last_update_ip": self.last_update_ip,
        }

    def send_session(self):
        global state
        r = None
        r = contactMAM(self.mam_id)
        self._processResponse(r)
        interruptable_sleep(300)
        return

    def _processResponse(self, jsonResponse: requests.Response) -> None:
        json_response_msg = ""
        global state
        try:
            json_response_msg = jsonResponse.json().get("msg", "").casefold()
            logger.info(f"Received response: '{json_response_msg}'")
        except ValueError:
            logger.error("API response was not in JSON")
            logger.error(
                f"HTTP response status code received: '{jsonResponse.status_code}'"
            )
            return
        except Exception as e:
            logger.error(f"Failed to decode JSON: {e}")
            return
        if jsonResponse.status_code == 200:
            self.last_update_ip = state.ip
            if json_response_msg:
                if json_response_msg == "Completed".casefold():
                    logger.info(f"MAM session IP successfully updated to: {state.ip}")
                    state.mam_ip_updated(self.mam_id, True)
                    return
                if json_response_msg == "No change".casefold():
                    logger.info(
                        f"Successful exchange with MAM, however IP matches "
                        f"current session as {state.ip}"
                    )
                    state.mam_ip_updated(self.mam_id, False)
                    return
                logger.info(
                    "Received status code 200 (OK) with"
                    f" unknown msg: '{json_response_msg}'"
                )
                state.mam_ip_updated(self.mam_id, False)
                return
            logger.info("Received status code 200 (ok) without a msg response")
            state.mam_ip_updated(self.mam_id, False)
            return
        if jsonResponse.status_code == 429:
            logger.warning(
                "MAM rejects due to last change too recent, "
                "and last successful update is unknown: retry in 15 minutes"
            )
            state.last_update_time = timeNow() - timedelta(minutes=46)
            return
        if jsonResponse.status_code == 403:
            if json_response_msg == "No Session Cookie".casefold():
                close_script("mam_id is not formatted correctly", 1)
            elif json_response_msg == "Invalid session - IP mismatch".casefold():
                close_script(
                    "Session invalidated due to IP mismatch"
                    " - make sure ASN lock is enabled",
                    1,
                )
            elif json_response_msg == "Invalid session - ASN mismatch".casefold():
                if not state.mismatched_asn:
                    logger.error("Could not update session IP due to ASN mismatch")
                    logger.error(
                        "Add the current IP to your MAM session to allow this ASN"
                    )
                    logger.error(f"Current IP: {state.ip}")
                    logger.error(f"Current ASN: {state.asn}")
                    logger.info(
                        "Checking for updated ASN permissions"
                        " with MAM every 5 minutes"
                    )
                    notify(
                        "mismatched ASN",
                        "Current mam_id was rejected by MAM."
                        " The session is not authorized to use the current ASN.",
                    )
                    state.mismatched_asn = True
                logger.debug("Received repeat ASN mismatch response from MAM")
            elif json_response_msg == "Invalid session - Invalid Cookie".casefold():
                close_script("Session invalid due to incorrectly formatted mam_id", 1)
            elif json_response_msg == "Incorrect session type - Other".casefold():
                close_script("session declared of incorrect type for unknown reason", 1)
            elif (
                json_response_msg
                == "Incorrect session type - not allowed this function".casefold()
            ):
                close_script("session is 'not allowed to use dynamic seedbox API'", 1)
            elif (
                json_response_msg
                == "Incorrect session type - non-API session".casefold()
            ):
                close_script("session does not have dynamic seedbox API enabled", 1)
            else:
                if json_response_msg:
                    logger.critical(
                        f"Received unknown msg from MAM: '{json_response_msg}'"
                    )
                close_script("Session declared invalid for unknown reason", 1)
            return
        logger.error("Could not process MAM's response")
        return


class TimeEnabledJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, datetime):
            obj = o.timestamp()
            return obj
        return super().default(o)


def notify(notification_title: str, notification_body: str) -> None:
    if env_notify_urls:
        apobj = apprise.Apprise()
        for url in env_notify_urls.split(","):
            url = url.strip()
            if url:
                apobj.add(url)
        apobj.notify(title=f"[mamapi]: {notification_title}", body=notification_body)


def close_script(
    exit_message: str,
    exit_code: int = 0,
    notify_title: str | None = None,
    notify_body: str | None = None,
) -> None:
    if exit_code == 0:
        logger.info(exit_message)
        logger.info("EXITING SCRIPT")
        sys.exit(0)
    if exit_code == 1:
        if notify_title and notify_body:
            notify(notify_title, notify_body)
        logger.critical(exit_message)
        logger.critical("EXITING SCRIPT")
        sys.exit(1)


def timeNow() -> datetime:
    return datetime.now(UTC)


def boolify_string(value: str | None) -> str | bool | None:
    if value is None:
        return None
    casefolded_value = value.casefold()
    if casefolded_value == "false":
        return False
    if casefolded_value == "true":
        return True
    return value


def loadData() -> None:
    global sessions, state, env_write_current_mamid
    logger.debug("Loading data from json")
    sessions.clear()
    try:
        with open(json_path) as f:
            data = json.load(f)
            if "state" in data:
                state.load(data["state"])
            for mam_id, session in data.get("sessions", {}).items():
                sessions[mam_id] = Session.from_dict(session)
    except FileNotFoundError:
        logger.info("Session data file not found, starting fresh")
    except json.JSONDecodeError:
        logger.warning("Session data file is corrupt or invalid, starting fresh")
    except PermissionError:
        close_script(
            "Permission error when reading session data file",
            1,
            "permission error",
            "Script closed due to error when reading session data from file.",
        )
    if env_write_current_mamid:
        try:
            logger.debug("Creating/blanking current_mamid file")
            with open(write_current_mamid_path, "w") as f:
                pass
        except Exception as e:
            logger.warning(f"Caught exception when making blank current_mamid: {e}")
            logger.warning("Disabling current_mamid writing")
            env_write_current_mamid = False


def saveData() -> None:
    global sessions, state, env_write_current_mamid
    saveDict = {
        "state": state.to_dict(),
        "sessions": {mam_id: session.to_dict() for mam_id, session in sessions.items()},
    }
    try:
        with open(json_path, "w") as f:
            json.dump(saveDict, f, indent=4, cls=TimeEnabledJSONEncoder)
    except (PermissionError, OSError) as e:
        close_script(
            f"Critical error writing session data: {e}",
            1,
        )
    if env_write_current_mamid and state.last_update_mamid:
        logger.debug("Writing current_mamid to file")
        try:
            with open(write_current_mamid_path, "w") as f:
                f.write(state.last_update_mamid)
        except (PermissionError, OSError) as e:
            logger.warning(f"Caught exception when writing current_mamid: {e}")
            logger.warning("Disabling current_mamid writing")
            env_write_current_mamid = False


def signal_handler(signal_number: int, frame: FrameType | None) -> None:
    raise SleepInterruptException()


def interruptable_sleep(sleeptime: float) -> None:
    try:
        time.sleep(sleeptime)
    except SleepInterruptException:
        close_script("Received close signal", 0)


def return_identity(
    return_current: bool = False,
) -> tuple[None, None] | tuple[str, str]:
    logger.debug("Attempting to grab external IP/ASN...")
    mamip_url = "https://t.myanonamouse.net/json/jsonIp.php"
    url = mamip_url
    try:
        r = requests.get(url, timeout=(5, 15))
    except requests.exceptions.ConnectionError:
        logger.debug("Failed internet check")
        return None, None
    except requests.exceptions.Timeout:
        logger.error("Request to external IP tracker timed out")
        return None, None
    except requests.exceptions.RequestException as err:
        logger.error(f"Unexpected error during HTTP GET: {err}")
        return None, None
    if r.status_code == 200:
        json_response_ip: str = r.json().get("ip", "")
        json_response_asn: str = r.json().get("ASN", "")
        if return_current:
            logger.info(f"Current IP: {json_response_ip}")
            logger.info(f"Current ASN: {json_response_asn}")
        return json_response_ip, json_response_asn
    else:
        logger.error("External IP/ASN check failed for unknown reason")
        return None, None


def contactMAM(inputMAMID: str) -> requests.Response:
    while True:
        for attempt in range(3):
            try:
                logger.info("Sending cookie to MAM...")
                r = requests.get(
                    "https://t.myanonamouse.net/json/dynamicSeedbox.php",
                    cookies={"mam_id": inputMAMID},
                    timeout=(5, 15),
                )
                logger.debug(f"Received HTTP status code: '{r.status_code}'")
                return r
            except requests.exceptions.ConnectionError:
                logger.error(f"No internet. Attempt #: {attempt + 1}")
            except requests.exceptions.Timeout:
                logger.error(f"Request timed out. Attempt #: {attempt + 1}")
            except requests.exceptions.RequestException as err:
                logger.error(f"Unexpected error during HTTP GET: {err}")
            if attempt < 2:
                interruptable_sleep(30)
        else:
            logger.error("Multiple HTTP GET failures: sleeping for 30 minutes")
            interruptable_sleep(1800)


def syncSessions() -> None:
    global sessions, env_mam_id
    logger.debug("Syncing env mam_ids with loaded sessions")
    cached_mam_ids = set(sessions.keys())
    for session_mam_id, _session_obj in list(sessions.items()):
        if session_mam_id != env_mam_id:
            logger.debug(
                f"mam_id exists in cache but not in env, deleting '{session_mam_id}'"
            )
            del sessions[session_mam_id]
    if env_mam_id not in cached_mam_ids:
        logger.debug(f"mam_id exists in env but not in cache, adding '{env_mam_id}'")
        sessions[env_mam_id] = Session(env_mam_id)
    if len(sessions) != 1:
        close_script(
            "ERROR: more than one session in cache, which should be impossible"
            " now. Please report this error",
            1,
        )
    saveData()


def mam_id_qualitycheck(mam_id: str | None) -> bool:
    if not mam_id:
        close_script("MAM_ID environment variable is empty", 1)
    if "@" in mam_id or "," in mam_id:  # type: ignore
        logger.critical(
            "Detected invalid characters (@ or ,) from discontinued multisession format"
        )
        close_script("Please set only one mam_id, without the @ip specifier", 1)
    return True


env_mam_id: str = os.getenv("MAM_ID")  # type: ignore
env_debug = boolify_string(os.getenv("DEBUG"))
env_write_current_mamid = boolify_string(os.getenv("WRITE_CURRENT_MAMID"))
env_notify_urls = os.getenv("NOTIFY_URLS")
env_shutdown_on_disconnect = boolify_string(os.getenv("SHUTDOWN_ON_DISCONNECT"))
write_current_mamid_path = Path("/data/current_mamid")
sessions: MutableMapping[str, Session] = {}
json_path = Path("/data/mamapi.json")
state = StateSingleton()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

try:
    logger.setLevel(logging.INFO)
    logger.info("STARTING SCRIPT")
    logger.info("https://github.com/elforkhead/mamapi")
    logger.info("v2.1 - replaces multisession with multiasn")
    logger.info("Checking for IP changes every 5 minutes")
    return_identity(True)
    if env_debug:
        logger.setLevel(logging.DEBUG)
        logger.info("Logger level: DEBUG (enabled by DEBUG env var)")
    mam_id_qualitycheck(env_mam_id)
    loadData()
    syncSessions()
    main_session = sessions[env_mam_id]
    while True:
        if state.ratelimited and state.last_update_time:
            logger.info(
                "Last successful IP update was at "
                f"{state.last_update_time.astimezone().strftime('%Y-%m-%d %H:%M')}. "
                f"Sleeping for {round(state.ratelimited / 60)} minutes"
            )
            interruptable_sleep(state.ratelimited)
            continue
        state.refresh()
        if state.ip == state.last_update_ip:
            logger.debug(
                "Current IP identical to last IP sent to MAM, sleeping for 5 minutes"
            )
            interruptable_sleep(300)
            continue
        logger.debug("Sending main session")
        main_session.send_session()
except SleepInterruptException:
    close_script("Received close signal", 0)
except Exception as e:
    close_script(f"Caught exception: {e}", 1)
