# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.




import json
import os
import re
import sys
import subprocess
from socket import AF_UNIX, SOCK_DGRAM, socket


# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_VT = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7


try:
    import requests
    from requests.exceptions import Timeout
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)



# ossec.conf configuration:
# <integration>
#   <name>GTI</name>
#   <api_key>API_KEY</api_key> <!-- Replace with your GTI API key -->
#   <group>syscheck</group>
#   <alert_format>json</alert_format>
# </integration>


# Global vars
debug_enabled = True
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}


# Log and socket path
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'
GTI_MALICIOUS_IP = f'{pwd}/etc/lists/gti_malicious_ips'
GTI_MALICIOUS_URL = f'{pwd}/etc/lists/gti_malicious_urls'
GTI_MALICIOUS_DOMAIN = f'{pwd}/etc/lists/gti_malicious_domains'
GTI_MALICIOUS_FILE_HASHES = f'{pwd}/etc/lists/gti_malicious_file_hashes'


GTI_FILE_MITRE_API = ""


# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7


VULN_INFO = {
    API = "https://www.virustotal.com/api/v3/collections/{id}",
    HEADER = {"accept": "application/json","x-apikey": ""}
}


FILE_MITRE_INFO = {
    API = "https://www.virustotal.com/api/v3/files/{id}/behaviour_mitre_trees",
    HEADER = {"accept": "application/json","x-apikey": ""}
}




def main(args):
    global debug_enabled
    global timeout
    global retries
    try:
        # Read arguments
        bad_arguments: bool = False
        msg = ''
        if len(args) >= 4:
            # debug_enabled = len(args) > 4 and args[4] == 'debug'
            if len(args) > TIMEOUT_INDEX:
                timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX:
                retries = int(args[RETRIES_INDEX])
        else:
            msg = '# Error: Wrong arguments\n'
            bad_arguments = True


        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg)


        if bad_arguments:
            debug('# Error: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)


        # Core function
        process_args(args)


    except Exception as e:
        debug(str(e))
        raise




def process_args(args) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields


    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running GTI script')


    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    apikey: str = args[APIKEY_INDEX]


    alert_key = ""
    oper_type = ""


    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")


    # # Request GTI info
    # debug(f'# Requesting GTI information {json_alert}')


    # msg: any = request_gti_info(oper_type, json_alert, apikey)


    # if not msg:
    #     debug('# Error: Empty message')
    #     raise Exception


    # send_msg(msg, json_alert['agent'])




def cdb_lookup(key, cdb_file):
    """
    Query a CDB list using cdblookup
    """
    try:
        result = subprocess.run(
            ["cdb -q", cdb_file, key],
            capture_output=True,
            text=True
        )


        value = result.stdout.strip()


        if value:
            return json.loads(value)


    except Exception:
        pass


    return None




# def extract_iocs(alert):
#     """
#     Extract IOCs from alert
#     Modify depending on your log sources
#     """


#     iocs = {
#         "ip": [],
#         "domain": [],
#         "url": [],
#         "hash": []
#     }


#     data = alert.get("data", {})


#     # IP
#     if "srcip" in data:
#         iocs["ip"].append(data["srcip"])


#     if "dstip" in data:
#         iocs["ip"].append(data["dstip"])


#     # Domain
#     if "domain" in data:
#         iocs["domain"].append(data["domain"])


#     if "hostname" in data:
#         iocs["domain"].append(data["hostname"])


#     # URL
#     if "url" in data:
#         iocs["url"].append(data["url"])


#     # File Hash
#     if "sha256" in data:
#         iocs["hash"].append(data["sha256"])


#     if "md5" in data:
#         iocs["hash"].append(data["md5"])


#     if "sha1" in data:
#         iocs["hash"].append(data["sha1"])


#     return iocs




# def enrich(alert):


#     iocs = extract_iocs(alert)


#     enrichment = {}


#     for ioc_type, values in iocs.items():


#         cdb_file = CDB_LISTS.get(ioc_type)


#         if not cdb_file:
#             continue


#         for v in values:


#             result = cdb_lookup(v, cdb_file)


#             if result:
#                 enrichment.setdefault(ioc_type, {})[v] = result


#     if enrichment:
#         alert["gti_enrichment"] = enrichment


#     return alert




def read_cdb_list(file_path, key_to_check):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()


                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()


                    if key == key_to_check:
                        debug(f"key check {key} {value}")
                        return value
    except FileNotFoundError:
        print("The file was not found.")


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled


    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')




def request_info_from_api(oper_type, alert_key, alert, alert_output, api_key):
    """Request information from an API using the provided alert and API key.


    Parameters
    ----------
    alert : dict
        The alert dictionary containing information for the API request.
    alert_output : dict
        The output dictionary where API response information will be stored.
    api_key : str
        The API key required for making the API request.


    Returns
    -------
    dict
        The response data received from the API.


    Raises
    ------
    Timeout
        If the API request times out.
    Exception
        If an unexpected exception occurs during the API request.
    """
    for attempt in range(retries + 1):
        try:
            if oper_type == "VULN":
                VULN_INFO["API"] = VULN_INFO.get("API").format(alert_key)
                VULN_INFO["HEADER"]["x-apikey"] = api_key
                vt_response_data = query_api(VULN_INFO)
            elif oper_type == "FILE":
                FILE_MITRE_INFO["API"] = FILE_MITRE_INFO.get("API").format(alert_key)
                FILE_MITRE_INFO["HEADER"]["x-apikey"] = api_key
                vt_response_data = query_api(FILE_MITRE_INFO)
            return vt_response_data
        except Timeout:
            debug('# Error: Request timed out. Remaining retries: %s' % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_VT)


    debug('# Error: Request timed out and maximum number of retries was exceeded')
    alert_output['GTI']['error'] = 408
    alert_output['GTI']['description'] = 'Error: API request timed out'
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_VT)


def request_gti_info(oper_type: str, alert_key: str, alert: any, apikey: str):
    """Generate the JSON object with the message to be send


    Parameters
    ----------
    alert : any
        JSON alert object.
    apikey : str
        The API key required for making the API request.


    Returns
    -------
    msg: str
        The JSON message to send
    """
    alert_output = {'GTI': {}, 'integration': 'GTI'}


    # # If there is no syscheck block present in the alert. Exit.
    # if 'syscheck' not in alert:
    #     debug('# No syscheck block present in the alert')
    #     return None


    # If there is no md5 checksum present in the alert. Exit.
    # if 'md5_after' not in alert['syscheck']:
    #     debug('# No md5 checksum present in the alert')
    #     return None


    # If the md5_after field is not a md5 hash checksum. Exit
    # if not (
    #     isinstance(alert['syscheck']['md5_after'], str) is True
    #     and len(re.findall(r'\b([a-f\d]{32}|[A-F\d]{32})\b', alert['syscheck']['md5_after'])) == 1
    # ):
    #     debug('# md5_after field in the alert is not a md5 hash checksum')
    #     return None




    # Request info using GTI API
    if oper_type == "IP":
        gti_response_data = read_cdb_list(GTI_MALICIOUS_IP, alert_key)
    elif oper_type == "URL":
        gti_response_data = read_cdb_list(GTI_MALICIOUS_URL, alert_key)
    elif oper_type == "DOMAIN":
        gti_response_data = read_cdb_list(GTI_MALICIOUS_DOMAIN, alert_key)
    elif oper_type == "FILE":
        gti_response_data = read_cdb_list(GTI_MALICIOUS_FILE_HASHES, alert_key)
        gti_file_mitre_reponse_data = request_info_from_api(oper_type, alert_key, alert, alert_output, apikey)
    else:
        gti_response_data = request_info_from_api(oper_type, alert_key, alert, alert_output, apikey)




    # alert_output['GTI']['found'] = 0
    # alert_output['GTI']['malicious'] = 0


    # Info about the file found in GTI
    # if alert_output['GTI']['found'] == 1:
    #     if gti_response_data['positives'] > 0:
    #         alert_output['GTI']['malicious'] = 1


    #     # Populate JSON Output object with GTI request
    #     alert_output['GTI'].update(
    #         {
    #             'sha1': vt_response_data['sha1'],
    #             'scan_date': vt_response_data['scan_date'],
    #             'positives': vt_response_data['positives'],
    #             'total': vt_response_data['total'],
    #             'permalink': vt_response_data['permalink'],
    #         }
    #     )


    return alert_output




def query_api(obj: dict) -> any:
    """Send a request to VT API and fetch information to build message


    Parameters
    ----------
    hash : str
        Hash need it for parameters
    apikey: str
        Authentication API


    Returns
    -------
    data: any
        JSON with the response


    Raises
    ------
    Exception
        If the status code is different than 200.
    """


    debug('# Querying GTI API')
    response = requests.get(
        obj.get("API"), headers=obj.get("HEADER"), timeout=timeout
    )


    if response.status_code == 200:
        json_response = response.json()
        vt_response_data = json_response
        return vt_response_data
    else:
        alert_output = {}
        alert_output['GTI'] = {}
        alert_output['integration'] = 'GTI'


        if response.status_code == 204:
            alert_output['GTI']['error'] = response.status_code
            alert_output['GTI']['description'] = 'Error: Public API request rate limit reached'
            send_msg(alert_output)
            raise Exception('# Error: GTI Public API request rate limit reached')
        elif response.status_code == 403:
            alert_output['GTI']['error'] = response.status_code
            alert_output['GTI']['description'] = 'Error: Check credentials'
            send_msg(alert_output)
            raise Exception('# Error: GTI credentials, required privileges error')
        else:
            alert_output['GTI']['error'] = response.status_code
            alert_output['GTI']['description'] = 'Error: API request fail'
            send_msg(alert_output)
            raise Exception('# Error: GTI credentials, required privileges error')




def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent['id'] == '000':
        string = '1:GTI:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any')
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->GTI:{1}'.format(location, json.dumps(msg))


    debug('# Request result from VT server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)




def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file


    Parameters
    ----------
    file_location : str
        Path to the JSON file location.


    Returns
    -------
    dict: any
        The JSON object read it.


    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
