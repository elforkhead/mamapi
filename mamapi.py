import sys
import os
import requests
import logging
import json
import time
import math
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

logNextSuccessfullIpCheck = False

current_ip = ""
mam_id = ""

json_path = Path('/data/mamapi.json')
json_data = {}

def timeNow():
    return datetime.now(timezone.utc)

def rateLimited(timestamp): #just tests if timestamp was more than 60 minutes ago, false if it was, also false if the timestamp is negative and we can't figure out how long if it has been
    if not timestamp:
        logger.debug(f"Returned False for ratelimited as provided empty parameter")
        return False
    logger.debug(f"rateLimited fxn: comparing NOW as '{timeNow().strftime('%Y-%m-%d %H:%M:%S')}' to provided timestamp '{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - should result in returning '{not ((timeNow() - timestamp) > timedelta(minutes=60))}'")
    return not ((timeNow() - timestamp) > timedelta(minutes=60))

def loadData():
    blankTemplate = {"last_successful_update": 0, "last_updated_ip": ""}
    try:
        with open(json_path) as f:
            data = json.load(f)
            if len(data) == len(blankTemplate):
                data["last_successful_update"] = datetime.fromtimestamp(data["last_successful_update"], timezone.utc)
                return data
            else:
                logger.warning("Number of entries in .json data does not match template, refreshing")
                return blankTemplate
    except (FileNotFoundError, json.JSONDecodeError):
        return blankTemplate
    except PermissionError:
        logger.critical("Loading .json data threw permission error - likely lacking read permission.")
        logger.critical("The script will now exit")
        sys.exit(1)

def saveData():
    json_serializable_data = json_data.copy()
    for key, value in json_serializable_data.items():
        if isinstance(value, datetime):
            json_serializable_data[key] = value.timestamp()
    with open(json_path, "w") as f:
        json.dump(json_serializable_data, f, indent=4)

def returnIP():
    global logNextSuccessfullIpCheck
    logger.debug("Attempting to grab external IP...")

    try:
        r = requests.get("https://api.ipify.org")
    except requests.exceptions.ConnectionError:
        logger.error(f"Failed to grab external IP - no internet")
        logNextSuccessfullIpCheck = True
        return False
    except requests.exceptions.Timeout:
        logger.error(f"Request to external IP tracker timed out")
        logNextSuccessfullIpCheck = True
        return False
    except requests.exceptions.RequestException as err:
        logger.error(f"Unexpected error during HTTP GET: {err}")
        logNextSuccessfullIpCheck = True
        return False

    if r.status_code == 200:
        if (logNextSuccessfullIpCheck):
            logger.info(f"Fetched external IP: {r.text}")
        else:
            logger.debug(f"Fetched external IP: {r.text}")

        logNextSuccessfullIpCheck = False
        return r.text
    else:
        logNextSuccessfullIpCheck = True
        return False

def chooseMAM_ID():
    if not os.getenv("MAM_ID"):
        logger.critical("No mam_id assigned to environment variable")
        logger.critical("The script will now exit")
        sys.exit(1)
    logger.debug(f"Using mam_id: {os.getenv("MAM_ID")}")
    return os.getenv("MAM_ID")

def contactMAM(inputMAMID):
    while True:
        for attempt in range(3):
            try:
                logger.info("Sending cookie to MAM...")
                r = requests.get("https://t.myanonamouse.net/json/dynamicSeedbox.php", cookies={"mam_id": inputMAMID})
                # r.raise_for_status()
                logger.debug(f"Received HTTP status code: '{r.status_code}'")
                if str(r.status_code) == "500":
                    logger.critical("Received HTTP status code '500'")
                    logger.critical("This is usually due to an incorrectly formatted mam_id")
                    logger.critical("The script will now exit")
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
        json_data["last_successful_update"] = 0
        saveData()
        time.sleep(1800)
    elif json_response_msg == "Incorrect session type".casefold():
        logger.critical("Per MAM: 'The session cookie is not to a locked session, or not a session that is allowed the dynamic seedbox setting'")
        logger.critical("The script will now exit")
        sys.exit(1)
    elif json_response_msg == "Invalid session".casefold():
        logger.critical("Per MAM: 'The system deemed the session invalid (bad mam_id value, or you've moved off the locked IP/ASN.'")
        logger.critical("I often encounter this error when using an ASN locked session. The API doesn't seem to invalidate sessions from an unexpected IP when IP locked, consider switching to an IP locked session")
        logger.critical("The script will now exit")
        sys.exit(1)
    elif json_response_msg == "No Session Cookie".casefold():
        logger.critical("Per MAM: 'You didn't properly provide the mam_id session cookie.'")
        logger.critical(f"Used the following mam_id for this request: {mam_id}")
        logger.critical("Your mam_id may be formatted incorrectly")
        logger.critical("The script will now exit")
        sys.exit(1)
    elif json_response_msg == "":
        logger.warning("MAM HTTP response did not include a 'msg'")
        logger.error(f"HTTP response status code received: '{jsonResponse.get("status_code")}'")
        time.sleep(300)
    else:
        logger.error(f"Received unknown json response message: {json_response_msg}")
        time.sleep(300)

try:
    logger.setLevel(logging.INFO)
    logger.info("Starting script. Thanks for using elforkhead's mamapi.py")
    logger.info("https://github.com/elforkhead/mamapi")
    if os.getenv("DEBUG"):
        logger.setLevel(logging.DEBUG)
        logger.info("Logger level: DEBUG (enabled by DEBUG env var)")
    else:
        logger.info("Logger level: INFO (default)")
        logger.info("Routine IP checks are not logged")
        logger.info("Log may appear empty if there are no IP changes")
    logger.info("Checking for IP changes every 5 minutes")
    mam_id = chooseMAM_ID()
    json_data = loadData()
    while True:
        current_ip = returnIP()
        if not current_ip:
            logger.error("Unable to fetch current IP. Sleeping for 10 minutes")
            time.sleep(600)
            continue
        if current_ip == json_data["last_updated_ip"]:
            logger.debug("Current IP identical to last update sent to MAM, sleeping for 5 minutes")
            time.sleep(300)
            continue
        elif rateLimited(json_data["last_successful_update"]):
            deltaTo60 = 0
            minutes_remaining = 0
            deltaTo60 = timedelta(hours=1) - (timeNow() - json_data["last_successful_update"])
            minutes_remaining = math.ceil(max(deltaTo60.total_seconds() / 60, 0))
            logger.info(f"Current IP ({current_ip}) is different than previous update ({json_data["last_updated_ip"]}), but we are currently rate limited.")
            logger.debug("rateLimited function returned positive: time delta calculated as {minutes_remaining} minutes")
            if minutes_remaining < 0:
                logger.error(f"Received a positive from rateLimited, but calculated inconsistent time delta of {minutes_remaining}. Sleeping for an hour and resetting update timestamp")
                json_data["last_successful_update"] = 0
                saveData()
                time.sleep(3600)
            else:
                logger.info(f"Last successful IP update was at {json_data["last_successful_update"]}. Sleeping for {minutes_remaining} minutes until an hour has passed")
                time.sleep((minutes_remaining * 60) + 2)
        else:
            logger.info(f"Detected IP change. Old IP: '{json_data["last_updated_ip"]}' New IP: '{current_ip}'")
            r = contactMAM(mam_id)
            processResponse(r)
            continue

except Exception as e:
    logger.critical(f"Caught exception: {e}")
    logger.critical("The script will now exit")
