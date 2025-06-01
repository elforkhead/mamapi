import json
import logging
import os
import signal
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

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


class SessionInvalidError(Exception):
    """Exception raised when mam session is declared invalid"""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(f"MAM session invalidated: {self.reason}")


class StateSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # Avoid reinitialization if already constructed
        if not hasattr(self, "_initialized"):
            self.last_update_ip = None
            self.last_update_asn = None
            self.last_update_mamid = None
            self.last_update_time = None
            self.ip = None
            self.asn = None
            self.no_current_options = False
            self.dumb_mode = False
            self.first_run = True
            self._initialized = True

    def to_dict(self):
        return {
            "last_update_ip": self.last_update_ip,
            "last_update_asn": self.last_update_asn,
            "last_update_mamid": self.last_update_mamid,
            "last_update_time": self.last_update_time,
        }

    def load(self, data: dict):
        self.last_update_ip = data.get("last_update_ip")
        self.last_update_asn = data.get("last_update_asn")
        self.last_update_mamid = data.get("last_update_mamid")
        provided_last_update_time = data.get("last_update_time")
        if provided_last_update_time:
            provided_last_update_time = datetime.fromtimestamp(
                provided_last_update_time, UTC
            )
            self.last_update_time = provided_last_update_time

    def refresh(self):
        latest_ip = returnIP()
        if not latest_ip:
            logger.error("Failed to grab external IP - no internet")
            logger.error("Checking for internet every 5 minutes")
            interruptable_sleep(300)
            while (latest_ip := returnIP()) is None:
                interruptable_sleep(300)
            logger.info(f"Connection restored. External IP: {latest_ip}")
        logger.debug(f"Fetched external IP: {latest_ip}")
        if self.ip != latest_ip:
            if (latest_ip != self.last_update_ip) and self.last_update_ip:
                logger.info("Detected IP change from last MAM session update")
                logger.info(f"Last MAM session IP: {self.last_update_ip}")
                logger.info(f"Current IP: {latest_ip}")
            self.ip = latest_ip
            if not self.dumb_mode:
                self.asn = lookup_asn(self.ip)
                if self.asn:
                    logger.info(f"Current ASN: {self.asn}")

    def mam_ip_updated(self, mamid: str, update_time: bool):
        global state
        self.last_update_ip = self.ip
        self.last_update_mamid = mamid
        if update_time:
            self.last_update_time = timeNow()
        if self.asn:
            self.last_update_asn = self.asn
        else:
            self.last_update_asn = None
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
        mam_id,
        original_session_ip=None,
        ASN=None,
        last_update_ip=None,
        invalid=False,
    ):
        self.mam_id = mam_id
        self.original_session_ip = original_session_ip
        self._ASN = ASN
        self.last_update_ip = last_update_ip
        self.invalid = invalid

    @classmethod
    def from_dict(cls, data):
        return cls(
            mam_id=data["mam_id"],
            original_session_ip=data["original_session_ip"],
            ASN=data["ASN"],
            last_update_ip=data["last_update_ip"],
            invalid=data["invalid"],
        )

    def to_dict(self):
        return {
            "mam_id": self.mam_id,
            "original_session_ip": self.original_session_ip,
            "ASN": self._ASN,
            "last_update_ip": self.last_update_ip,
            "invalid": self.invalid,
        }

    @property
    def ASN(self):
        global state
        ip = None
        if state.dumb_mode:
            logger.debug("Skipping session ASN getter due to dumb_mode")
            return None
        if self._ASN is not None:
            return self._ASN
        if self.last_update_ip:
            ip = self.last_update_ip
        elif self.original_session_ip:
            ip = self.original_session_ip
        if ip:
            output = lookup_asn(ip)
            if output:
                self._ASN = output
                logger.debug(f"Fetched ASN '{output}' for mam_id: {self.mam_id}")
                saveData()
                return output
            return None

    def send_session(self):
        global state
        state.no_current_options = False
        r = None
        try:
            r = contactMAM(self.mam_id)
            self._processResponse(r)
            interruptable_sleep(300)
            return True
        except SessionInvalidError as e:
            logger.critical(f"{e}")
            self.invalidate()
            return False

    def _processResponse(self, jsonResponse):
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
        if json_response_msg == "Completed".casefold():
            logger.info(f"MAM session IP successfully updated to: {state.ip}")
            self.last_update_ip = state.ip
            state.mam_ip_updated(self.mam_id, True)
            return
        elif json_response_msg == "No change".casefold():
            logger.info(
                f"Successful exchange with MAM, however IP matches "
                f"current session as {state.ip}"
            )
            self.last_update_ip = state.ip
            state.mam_ip_updated(self.mam_id, False)
            return
        elif jsonResponse.status_code == 429:
            logger.warning(
                "MAM rejects due to last change too recent, "
                "and last successful update is unknown: retry in 15 minutes"
            )
            state.last_update_time = timeNow() - timedelta(minutes=46)
            return
        elif json_response_msg == "":
            logger.warning("MAM HTTP response did not include a 'msg'")
            logger.warning(
                f"HTTP response status code received: '{jsonResponse.status_code}'"
            )
            return
        elif json_response_msg == "Incorrect session type".casefold():
            logger.critical(
                "Per MAM: 'The session cookie is not to a locked session, "
                "or not a session that is allowed the dynamic seedbox setting'"
            )
            raise SessionInvalidError("Response: incorrect session type")
        elif json_response_msg == "Invalid session".casefold():
            logger.critical(
                "Per MAM: 'The system deemed the session invalid (bad mam_id value, "
                "or you've moved off the locked IP/ASN)'"
            )
            raise SessionInvalidError("Response: invalid session")
        elif json_response_msg == "No Session Cookie".casefold():
            logger.critical(
                "Per MAM: 'You didn't properly provide the mam_id session cookie.'"
            )
            logger.critical("Your mam_id may be formatted incorrectly")
            raise SessionInvalidError("Response: no session cookie")
        else:
            logger.error(f"Received unknown json response message: {json_response_msg}")
            return

    def invalidate(self):
        logger.critical("INVALID SESSION:")
        logger.critical(f"mam_id: {self.mam_id}")
        logger.critical(f"original IP: {self.original_session_ip}")
        logger.critical(f"last update IP: {self.last_update_ip}")
        self.invalid = True
        saveData()


class SessionSetsSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # Avoid reinitialization if already constructed
        if not hasattr(self, "_initialized"):
            self._initialized = True

    @property
    def valids(self) -> set[Session]:
        global sessions
        valids: set[Session] = set()
        for _mam_id, session in sessions.items():
            if not session.invalid:
                valids.add(session)
        return valids

    @property
    def invalids(self) -> set[Session]:
        global sessions
        invalids: set[Session] = set()
        for _mam_id, session in sessions.items():
            if session.invalid:
                invalids.add(session)
        return invalids

    @property
    def ips(self) -> dict[str, Session]:
        # will use original session ip if there is no last update
        # returns a dict with key as ip and value as session
        global sessions
        ips: dict[str, Session] = {}
        for _mam_id, session in sessions.items():
            if session.invalid:
                continue
            if isinstance(session.last_update_ip, str):
                if session.last_update_ip in ips:
                    logger.warning(
                        "While building IP list, duplicate was found - "
                        "invaliding session"
                    )
                    session.invalidate()
                    continue
                ips[session.last_update_ip] = session
                continue
            if isinstance(session.original_session_ip, str):
                if session.original_session_ip in ips:
                    logger.warning(
                        "While building IP list, duplicate was found - "
                        "invaliding session"
                    )
                    session.invalidate()
                    continue
                ips[session.original_session_ip] = session
                continue
        return ips

    @property
    def asns(self) -> dict[str, Session]:
        global sessions
        asns: dict[str, Session] = {}
        for _mam_id, session in sessions.items():
            if session.invalid:
                continue
            if isinstance(session.ASN, str):
                if session.ASN in asns:
                    logger.warning(
                        "While building ASN list, duplicate was found - "
                        "invaliding session"
                    )
                    session.invalidate()
                    continue
                asns[session.ASN] = session
        return asns


class TimeEnabledJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            obj = o.timestamp()
            return obj
        return super().default(o)


def lookup_asn(ip) -> str | bool:
    url = f"https://api.hackertarget.com/aslookup/?q={ip}&output=json"
    # url = f"https://api.ipinfo.io/lite/{ip}" probably blocks vpns
    try:
        logger.debug(f"ASN lookup for: {ip}")
        response = requests.get(url, timeout=(5, 15))
        response.raise_for_status()
        data = response.json()
        logger.debug(f"ASN lookup response: {data.get('asn', '')}")
        asn = data.get("asn", "")
        return asn if asn else False
    except requests.RequestException as e:
        logger.error(
            f"Error fetching ASN: {e}"
        )  # will need more elaborate error processing for poorly formatted ips and such
        return False


def timeNow():
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


def loadData():
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
        logger.warning("Session data file not found, starting fresh")
    except json.JSONDecodeError:
        logger.warning("Session data file is corrupt or invalid, starting fresh")
    except PermissionError:
        logger.critical("Permission error when reading session data file")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    if env_write_current_mamid:
        try:
            logger.debug("Creating/blanking current_mamid file")
            with open(write_current_mamid_path, "w") as f:
                pass
        except Exception as e:
            logger.warning(f"Caught exception when making blank current_mamid: {e}")
            logger.warning("Disabling current_mamid writing")
            env_write_current_mamid = False


def saveData():
    global sessions, state, env_write_current_mamid
    saveDict = {
        "state": state.to_dict(),
        "sessions": {mam_id: session.to_dict() for mam_id, session in sessions.items()},
    }
    with open(json_path, "w") as f:
        json.dump(saveDict, f, indent=4, cls=TimeEnabledJSONEncoder)
    if env_write_current_mamid and state.last_update_mamid:
        logger.debug("Writing current_mamid to file")
        try:
            with open(write_current_mamid_path, "w") as f:
                f.write(state.last_update_mamid)
        except Exception as e:
            logger.warning(f"Caught exception when writing current_mamid: {e}")
            logger.warning("Disabling current_mamid writing")
            env_write_current_mamid = False


def signal_handler(signal_number, frame) -> None:
    raise SleepInterruptException()


def interruptable_sleep(sleeptime: float) -> None:
    try:
        time.sleep(sleeptime)
    except SleepInterruptException:
        logger.info("Received close signal")
        logger.info("EXITING SCRIPT")
        sys.exit(0)


def returnIP() -> None | str:
    global state
    logger.debug("Attempting to grab external IP...")
    try:
        r = requests.get("https://api.ipify.org", timeout=(5, 15))
    except requests.exceptions.ConnectionError:
        logger.debug("Failed internet check")
        return None
    except requests.exceptions.Timeout:
        logger.error("Request to external IP tracker timed out")
        return None
    except requests.exceptions.RequestException as err:
        logger.error(f"Unexpected error during HTTP GET: {err}")
        return None
    if r.status_code == 200:
        return r.text
    else:
        logger.error("External IP check failed for unknown reason")
        return None


def briefReturnIP() -> bool:
    try:
        r = requests.get("https://api.ipify.org", timeout=(5, 15))
    except requests.exceptions.RequestException as e:
        logger.error(f"Initialization IP check failed: {e}")
        return False
    if r.status_code == 200:
        logger.info(f"Current IP: {r.text}")
        return True
    else:
        logger.error("Initialization IP check failed")
        return False


def contactMAM(inputMAMID: str):
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


def parseMAMID() -> dict[str, str | None]:
    global state
    logger.debug("Parsing env mamids")
    env = os.getenv("MAM_ID")
    if not env:
        logger.critical("No mam_ids assigned to environment variable")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    entries = env.split(",")
    parsed_mamids: dict[str, str | None] = {}
    for entry in entries:
        parts = entry.strip().split("@")
        mam_id = parts[0].strip()
        original_ip = parts[1].strip() if len(parts) == 2 else None
        if (len(entries) != 1) and (not original_ip):
            logger.warning(f"Skipping mam_id with missing ip in entry: '{entry}'")
            continue
        if not mam_id:
            logger.warning(f"Skipping empty mam_id in entry: '{entry}'")
            continue
        parsed_mamids[mam_id] = original_ip
    if len(parsed_mamids) == 0:
        logger.critical("Parsing mam_id environment variable returned no mam_ids")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    if len(parsed_mamids) == 1:
        for _mam_id, original_ip in parsed_mamids.items():
            if not original_ip:
                state.dumb_mode = True
                logger.info(
                    "Received one mam_id without IP session info - "
                    "assuming ASN unaware behavior is preferred"
                )
    if env_debug:
        logger.debug("Successfully parsed the following mam_ids:")
        for mam_id, original_ip in parsed_mamids.items():
            logger.debug(f"mam_id: {mam_id}")
            logger.debug(f"original_ip: {original_ip}")
    return parsed_mamids


def syncSessions():
    global sessions
    parsed_mamids = parseMAMID()
    logger.debug("Syncing env mam_ids with loaded sessions")
    env_mam_ids = set(parsed_mamids.keys())
    cached_mam_ids = set(sessions.keys())
    for session_mam_id, _session_obj in list(sessions.items()):
        if session_mam_id not in env_mam_ids:
            logger.info(
                f"mam_id exists in cache but not in env, deleting '{session_mam_id}'"
            )
            del sessions[session_mam_id]
    for env_mam_id in env_mam_ids:
        if env_mam_id in cached_mam_ids:
            continue
        logger.info(f"mam_id exists in env but not in cache, adding '{env_mam_id}'")
        sessions[env_mam_id] = Session(env_mam_id, parsed_mamids[env_mam_id])
    saveData()


env_debug = boolify_string(os.getenv("DEBUG"))
env_write_current_mamid = boolify_string(os.getenv("WRITE_CURRENT_MAMID"))
write_current_mamid_path = Path("/data/current_mamid")
sessions: dict[str, Session] = {}
json_path = Path("/data/mamapi_multisession.json")
session_sets = SessionSetsSingleton()
state = StateSingleton()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

try:
    logger.setLevel(logging.INFO)
    logger.info("STARTING SCRIPT")
    logger.info("https://github.com/elforkhead/mamapi")
    logger.info("v2.0 - now with support for multiple mam_ids and ASNs")
    logger.info("Checking for IP changes every 5 minutes")
    briefReturnIP()
    if env_debug:
        logger.setLevel(logging.DEBUG)
        logger.info("Logger level: DEBUG (enabled by DEBUG env var)")
    loadData()
    syncSessions()
    if session_sets.invalids:
        logger.warning(
            "Detected the following invalid mam_ids/sessions - "
            "remove these from your env"
        )
        for session in session_sets.invalids:
            logger.warning("INVALID SESSION:")
            logger.warning(f"mam_id: {session.mam_id}")
            logger.warning(f"original IP: {session.original_session_ip}")
            logger.warning(f"last update IP: {session.last_update_ip}")
    while True:
        if not state.dumb_mode:
            for session in session_sets.valids:
                if not session.ASN:
                    if state.first_run:
                        logger.warning(
                            f"Could not grab ASN on initialization for "
                            f"session: {session.mam_id}"
                        )
        state.first_run = False
        if not session_sets.valids:
            logger.critical(
                "No available valid sessions - "
                "wipe all of your env mam_ids and start fresh"
            )
            logger.critical("EXITING SCRIPT")
            sys.exit(1)
        if state.ratelimited and state.last_update_time:
            logger.info(
                f"Last successful IP update was at "
                f"{state.last_update_time.astimezone().strftime('%Y-%m-%d %H:%M')}. "
                "Sleeping for {round(state.ratelimited / 60)} minutes"
            )
            interruptable_sleep(state.ratelimited)
            continue
        state.refresh()
        if state.ip == state.last_update_ip:
            logger.debug(
                "Current IP identical to last update sent to MAM, "
                "sleeping for 5 minutes"
            )
            interruptable_sleep(300)
            continue
        if state.dumb_mode:
            if len(sessions) != 1:
                logger.critical(
                    "ERROR: entered dumb_mode with more than one session. "
                    "Please report this error"
                )
                logger.critical("EXITING SCRIPT")
                sys.exit(1)
            for session in sessions.values():
                logger.debug("Sending dumb session...")
                session.send_session()
            continue
        if not state.asn:
            logger.warning(
                "Could not retrieve current ASN, "
                "the ASN API may be invalid or ratelimited"
            )
            logger.warning("Retrying in 5 minutes")
            interruptable_sleep(300)
            continue
        if state.ip in session_sets.ips:
            logger.info(
                "Current IP is associated with a mam_id. "
                "Sending update with matching mam_id..."
            )
            session_sets.ips[state.ip].send_session()
            continue
        if state.asn in session_sets.asns:
            logger.info(
                "Current ASN is associated with a mam_id. "
                "Sending update with matching mam_id..."
            )
            session_sets.asns[state.asn].send_session()
            continue
        if not state.no_current_options:
            logger.warning(
                "No sessions matching the current IP or ASN exist, will recheck "
                "every 5 minutes in case the IP changes to a matching IP/ASN"
            )
            logger.warning(
                "This can occur if the script fails to fetch ASNs for your mam_ids"
            )
            logger.warning(
                f"Consider making an additional session to "
                f"match the current IP: '{state.ip}'"
            )
        state.no_current_options = True
        interruptable_sleep(300)
except SleepInterruptException:
    logger.info("Received close signal")
    logger.info("EXITING SCRIPT")
    sys.exit(0)
except Exception as e:
    logger.critical(f"Caught exception: {e}")
    logger.critical("EXITING SCRIPT")
    sys.exit(1)