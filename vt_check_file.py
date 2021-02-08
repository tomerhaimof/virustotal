#!/usr/bin/python3

'''
    This script will get a file as an argument and will output it's detections from VirusTotal (vt)
    In order to print the FULL analyses, please add "full" after the file name:
        
        ./vt_check_file.py filename
        OR
        ./vt_check_file.py filename full

    Tomer Haimof
'''

from getpass import getpass
import sys
from os import path
import time
import hashlib
import calendar
import json
import requests

BASE_URL = "https://www.virustotal.com/api/v3"

def get_vt_api_key():
    '''
        Get the vt api key from the user and return it.
    '''
    vt_key = ""
    while vt_key == "":
        vt_key = getpass("Please enter VT key")
    return vt_key

def check_vt_key(vt_key):
    '''
        vt_key - VirusTotal api key
        Check if the api key is valid.
        return "verified" if it is valid.
        If not - return the error code
    '''
    headers = {'x-apikey': vt_key}
    res = requests.get(BASE_URL + '/search?query=blablasomestringblabla', headers=headers)
    if res.status_code == 401:
        return res.json()['error']['code']
    else:
        return "verified"

def sha256sum(filename):
    '''
        return the sha256 hash of a given file
    '''
    hash_256 = hashlib.sha256()
    byte_array = bytearray(128*1024)
    mem_view = memoryview(byte_array)
    with open(filename, 'rb', buffering=0) as file:
        for num in iter(lambda : file.readinto(mem_view), 0):
            hash_256.update(mem_view[:num])
    return hash_256.hexdigest()

def pretty_json(json_dict):
    '''
        get a json as dict and return pretty json
    '''
    return json.dumps(json_dict, indent=4, sort_keys=True)

def main():
    '''
        Main function
    '''

    # Check if a file was given as an argument
    if len(sys.argv) < 2:
        print("Please provide a full file path:\n\t%s /full/file/path.ext" % sys.argv[0] \
            + "\nIn order to print the FULL response, please run "\
            + "\n\t%s /full/file/path.ext full" % sys.argv[0])
        sys.exit()
    full = False
    if len(sys.argv) == 3:
        if sys.argv[2] == "full":
            full = True
    # Check if the given file exists
    if not path.exists(sys.argv[1]):
        print("File doesn't exist!")
        sys.exit()

    vt_key = get_vt_api_key()
    vt_key_status = check_vt_key(vt_key)
    if vt_key_status != "verified":
        print("Error: %s" % vt_key_status)
        sys.exit()
    file_name = sys.argv[1]
    data = {'file': open(file_name, 'rb')}
    headers = {'x-apikey': vt_key}
    file_sha256 = sha256sum(file_name)
    session = requests.Session()
    # Check if the file has been analysed already by submitting it's hash
    res = session.get(BASE_URL + '/files/' + file_sha256, headers=headers)
    file_id = ""
    if 'error' not in res.json() and len(res.json()['data']) > 0:
        epoch_time = calendar.timegm(time.gmtime())
        # If the last analysis was more than 24 hours ago, reanalyse
        if int((res.json()['data']['attributes']['last_analysis_date']) + 86400) < epoch_time:
            res = session.post(BASE_URL + '/files/' + file_sha256 + '/analyse', headers=headers)
            file_id = res.json()['data']['id']
        else:
            print("File Detections:\n----------------")
            if full is False:
                print(pretty_json(res.json()['data']['attributes']['last_analysis_stats']))
            else:
                print(pretty_json(res.json()))
            sys.exit()

    # If the hash wasn't found or it was analysed more than 24 hours ago
    if file_id == "":
        file_size_bytes = path.getsize(file_name)
        # If file size is bigger then 32Mb, we need to get a unique upload url first
        if file_size_bytes > 32000000:
            res = session.get(BASE_URL + "/files/upload_url", headers=headers)
            upload_url = res.json()['data']
            print("Uploading file, please wait...")
            res = session.post(upload_url, files=data, headers=headers)
        else:
            res = session.post(BASE_URL + "/files", files=data, headers=headers)
        file_id = res.json()['data']['id']
    res = session.get(BASE_URL + "/analyses/" + file_id, headers=headers)
    status = res.json()['data']['attributes']['status']
    # A file analysing can take some time. Print the output only when it's ready.
    while status == 'queued':
        print("Waiting for file status, please wait...")
        time.sleep(10)
        res = session.get(BASE_URL + "/analyses/" + file_id, headers=headers)
        status = res.json()['data']['attributes']['status']
    res = session.get(BASE_URL + '/files/' + file_sha256, headers=headers)
    print("File Detections:\n----------------")
    if full is False:
        print(pretty_json(res.json()['data']['attributes']['last_analysis_stats']))
    else:
        print(pretty_json(res.json()))

if __name__ == '__main__':
    main()
