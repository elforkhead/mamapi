import sys
import os
import requests
import logging
import json
import time
import math
import copy
from pathlib import Path
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="[%Y-%m-%d %H:%M:%S]")
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG) # intended to handle DEBUG and INFO
stdout_handler.setFormatter(formatter)
stdout_handler.addFilter(lambda record: record.levelno < logging.WARNING)
stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.WARNING)  # intended to handle WARNING, ERROR, CRITICAL
stderr_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)
logger.addHandler(stderr_handler)

class Client:
    pass

class Session:
    def __init__(self):
        self.mam_id = ""
        self._ASN = None
        self.last_update_time = ""
        self.last_update_ip = ""
        self.invalid = False
        self.original_session_ip = ""
        
    @property
    def ASN(self):
        ip = None
        if self._ASN != None:
            return self._ASN
        if self.last_update_ip:
            ip = self.last_update_ip
        elif self.original_session_ip:
            ip = self.original_session_ip
        if ip:
            output = lookup_asn(ip)
            if output:
                self._ASN = output
                return output
        
    @ASN.setter
    def ASN(self, value):
        self._ASN = value

def lookup_asn(ip):
    url = f"https://api.hackertarget.com/aslookup/?q={ip}&output=json"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        logger.debug
        return data.get("asn", "")
    except requests.RequestException as e:
        logger.error(f"Error fetching ASN: {e}") # will need more elaborate error processing for poorly formatted ips and such
        return False


current_ip = ""
mam_id = ""
first_run = True

internet_is_out = False

json_path = Path('/data/mamapi.json')
json_data = {}
blankTemplate = {"last_successful_update": 0, "last_updated_ip": "", "last_mam_id": "", "last_mam_id_invalid": False}

def timeNow():
    return datetime.now(timezone.utc)

def rateLimited(timestamp):
    if not timestamp:
        logger.debug(f"Returned False for ratelimited as provided empty parameter")
        return False
    return (timeNow() - timestamp) <= timedelta(minutes=60)

def loadData():
    try:
        with open(json_path) as f:
            data = json.load(f)
            if set(data.keys()) == set(blankTemplate.keys()):
                data["last_successful_update"] = datetime.fromtimestamp(data["last_successful_update"], timezone.utc)
                return data
            else:
                logger.warning("Number of entries in .json data does not match template, refreshing")
                return blankTemplate
    except (FileNotFoundError, json.JSONDecodeError):
        return blankTemplate
    except PermissionError:
        logger.critical("Loading .json data threw permission error - likely lacking read permission.")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)

def saveData():
    json_serializable_data = copy.deepcopy(json_data)
    for key, value in json_serializable_data.items():
        if isinstance(value, datetime):
            json_serializable_data[key] = value.timestamp()
    with open(json_path, "w") as f:
        json.dump(json_serializable_data, f, indent=4)

def returnIP():
    global internet_is_out
    logger.debug("Attempting to grab external IP...")
    try:
        r = requests.get("https://api.ipify.org")
    except requests.exceptions.ConnectionError:
        if not internet_is_out:
            logger.error("Failed to grab external IP - no internet")
            logger.error("Checking for internet every 5 minutes")
        logger.debug("Failed internet check")
        internet_is_out = True
        time.sleep(300)
        return False
    except requests.exceptions.Timeout:
        logger.error(f"Request to external IP tracker timed out")
        logger.error("Sleeping for 10 minutes")
        internet_is_out = True
        time.sleep(600)
        return False
    except requests.exceptions.RequestException as err:
        logger.error(f"Unexpected error during HTTP GET: {err}")
        logger.error("Sleeping for 10 minutes")
        internet_is_out = True
        time.sleep(600)
        return False
    if r.status_code == 200:
        if internet_is_out:
            logger.info("Connection restored")
            logger.info(f"Fetched external IP: {r.text}")
            internet_is_out = False
            return r.text
        else:
            logger.debug(f"Fetched external IP: {r.text}")
            return r.text
    else:
        logger.error("External IP check failed for unknown reason")
        logger.error("Sleeping for 10 minutes")
        internet_is_out = True
        time.sleep(600)
        return False

def briefReturnIP():
    try:
        r = requests.get("https://api.ipify.org")
    except requests.exceptions.RequestException as e:
        logger.error(f"Initialization IP check failed: {e}")
        return False
    if r.status_code == 200:
        logger.info(f"Current IP: {r.text}")
        return True
    else:
        logger.error("Initialization IP check failed")
        return False

def chooseMAM_ID():
    global json_data
    env_mam_id = os.getenv("MAM_ID")
    if not env_mam_id:
        logger.critical("No mam_id assigned to environment variable")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    if json_data["last_mam_id_invalid"] and (env_mam_id == json_data["last_mam_id"]):
        logger.critical("This mam_id/session was previously marked as invalid")
        logger.critical("Please generate a new mam_id/session")
        logger.critical("See the thread for the latest discussion of this issue")
        logger.critical("If you are still seeing this after changing your mam_id, you may need to rebuild the container to apply the new value")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    if env_mam_id != json_data["last_mam_id"]:
        logger.info("Detected new mam_id - clearing previous session data")
        json_data = blankTemplate.copy()
        json_data["last_mam_id"] = env_mam_id
        saveData()
    logger.debug(f"Using mam_id: {env_mam_id}")
    return env_mam_id

def contactMAM(inputMAMID):
    while True:
        for attempt in range(3):
            try:
                logger.info("Sending cookie to MAM...")
                r = requests.get("https://t.myanonamouse.net/json/dynamicSeedbox.php", cookies={"mam_id": inputMAMID})
                # r.raise_for_status()
                logger.debug(f"Received HTTP status code: '{r.status_code}'")
                if r.status_code == 500:
                    logger.critical("Received HTTP status code '500'")
                    logger.critical("This is usually due to an incorrectly formatted mam_id")
                    logger.critical("EXITING SCRIPT")
                    sys.exit(1)
                return r
            except requests.exceptions.ConnectionError:
                logger.error(f"No internet. Attempt #: {attempt + 1}")
            except requests.exceptions.Timeout:
                logger.error(f"Request timed out. Attempt #: {attempt + 1}")
            # except requests.exceptions.HTTPError as err:
            #     logger.error(f"HTTP error: '{err}'. Attempt #: {attempt + 1}") this is grabbing stuff before i can process the message
            except requests.exceptions.RequestException as err:
                logger.error(f"Unexpected error during HTTP GET: {err}")
            if attempt < 2:
                time.sleep(30)
        else:
            logger.error("Multiple HTTP GET failures: sleeping for 30 minutes")
            time.sleep(1800)

def processResponse(jsonResponse):
    json_response_msg = ""
    try:
        json_response_msg = jsonResponse.json().get("msg", "").casefold()
        logger.info(f"Received response: '{json_response_msg}'")
    except ValueError:
        logger.error("API response was not in JSON")
        logger.error(f"HTTP response status code received: '{jsonResponse.status_code}'")
    if json_response_msg == "Completed".casefold():
        logger.info(f"MAM session IP successfully updated to: {current_ip}")
        logger.info("Sleeping for 1 hour (earlier requests would be ratelimited)")
        json_data["last_updated_ip"] = current_ip
        json_data["last_successful_update"] = timeNow()
        saveData()
        time.sleep(3660)
    elif json_response_msg == "No change".casefold():
        logger.info(f"Successful exchange with MAM, however IP matches current session as {current_ip}")
        json_data["last_updated_ip"] = current_ip
        saveData()
        time.sleep(300)
    elif json_response_msg == "Last Change too recent".casefold():
        logger.warning("MAM rejects due to last change too recent, and last successful update is unknown: retrying in 30 minutes")
        json_data["last_successful_update"] = datetime.fromtimestamp(0, timezone.utc)
        saveData()
        time.sleep(1800)
    elif json_response_msg == "Incorrect session type".casefold():
        logger.critical("Per MAM: 'The session cookie is not to a locked session, or not a session that is allowed the dynamic seedbox setting'")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    elif json_response_msg == "Invalid session".casefold():
        logger.critical("Per MAM: 'The system deemed the session invalid (bad mam_id value, or you've moved off the locked IP/ASN)'")
        logger.critical("See the thread for the latest discussion of this issue")
        logger.debug("Marking current mam_id as invalid")
        json_data["last_mam_id_invalid"] = True
        saveData()
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    elif json_response_msg == "No Session Cookie".casefold():
        logger.critical("Per MAM: 'You didn't properly provide the mam_id session cookie.'")
        logger.critical(f"Used the following mam_id for this request: {mam_id}")
        logger.critical("Your mam_id may be formatted incorrectly")
        logger.critical("EXITING SCRIPT")
        sys.exit(1)
    elif json_response_msg == "":
        logger.warning("MAM HTTP response did not include a 'msg'")
        logger.error(f"HTTP response status code received: '{jsonResponse.status_code}'")
        time.sleep(300)
    else:
        logger.error(f"Received unknown json response message: {json_response_msg}")
        time.sleep(300)

try:
    logger.setLevel(logging.INFO)
    logger.info("STARTING SCRIPT")
    logger.info("https://github.com/elforkhead/mamapi")
    briefReturnIP()
    if os.getenv("DEBUG"):
        logger.setLevel(logging.DEBUG)
        logger.info("Logger level: DEBUG (enabled by DEBUG env var)")
    logger.info("Checking for IP changes every 5 minutes")
    json_data = loadData()
    mam_id = chooseMAM_ID()
    while True:
        current_ip = returnIP()
        if not current_ip:
            continue
        if current_ip == json_data["last_updated_ip"]:
            if first_run:
                logger.info("Current IP matches last recorded update sent to MAM")
                first_run = False
            logger.debug("Current IP identical to last update sent to MAM, sleeping for 5 minutes")
            time.sleep(300)
            continue
        if rateLimited(json_data["last_successful_update"]):
            deltaTo60 = 0
            minutes_remaining = 0
            deltaTo60 = timedelta(hours=1) - (timeNow() - json_data["last_successful_update"])
            minutes_remaining = math.ceil(max(deltaTo60.total_seconds() / 60, 0))
            logger.info(f"Current IP ({current_ip}) is different than previous update ({json_data['last_updated_ip']}), but we are currently rate limited.")
            logger.debug(f"rateLimited function returned positive: time delta calculated as {minutes_remaining} minutes")
            logger.info(f"Last successful IP update was at {json_data['last_successful_update'].astimezone().strftime('%Y-%m-%d %H:%M')}. Sleeping for {minutes_remaining} minutes until an hour has passed")
            first_run = False
            time.sleep((minutes_remaining * 60) + 2)
        else:
            first_run = False
            if json_data["last_updated_ip"]:
                logger.info(f"Detected IP change. Old IP: '{json_data['last_updated_ip']}' New IP: '{current_ip}'")
            else:
                logger.info("No recorded session IP - attempting to update session")
            r = contactMAM(mam_id)
            processResponse(r)
            continue
except Exception as e:
    logger.critical(f"Caught exception: {e}")
    logger.critical("EXITING SCRIPT")
