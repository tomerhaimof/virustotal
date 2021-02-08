#!/usr/bin/python3

'''
    This script will get a url as an argument and will output it's detections
    and categories from VirusTotal (vt). Plese note that if the last analysis
    was conducted more than 24 hours ago, the script will ask for a new 
    which may take some time.
    In order to print the FULL analyses, please add "full" after the url:
        
        ./vt_check_url.py "https://some.url.here/blabla.html"
        OR
        ./vt_check_url.py "https://some.url.here/blabla.html" full

    Tomer Haimof
'''

from getpass import getpass
import sys
import time
import calendar
import json
import base64
import re
import requests

BASE_URL = "https://www.virustotal.com/api/v3"

URL_REGEX_PATTERN = r"(https?:\/\/((((?<![\.0-9])[0-9]|(?<![\.0-9])([1-9][0-9])|(?<![\.0-9])(1[0-9]{2})|" \
 + r"(?<![\.0-9])(2[0-4][0-9]|25[0-5]))\.(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)" \
 + r"{2}([0-9](?![\.0-9])|([1-9][0-9])(?![\.0-9])|(1[0-9]{2})(?![\.0-9])|(2[0-4][0-9])" \
 + r"(?![\.0-9])|(25[0-5])(?![\.0-9])))|(([0-9a-zA-Z\-]?)*\.)+(aero|asia|biz|cat|com|coop|edu|gov|" \
 + "info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|" \
 + "ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|" \
 + "cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi" \
 + "|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|" \
 + "hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|" \
 + "li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my" \
 + "|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|" \
 + "qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|" \
 + "tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws" \
 + r"|ye|yt|yu|za|zm|zw))(\/[^\"^\{^\}^'^\(^\)^ ^>^\s^\*^<^>^\\\,]*[\,\"\{\}' \(\)>]{0})?)"

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
    return "verified"

def get_url_base64(url):
    '''
        return a url encoded as base64 without padding
    '''
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id

def pretty_json(json_dict):
    '''
        get a json as dict and return pretty json
    '''
    return json.dumps(json_dict, indent=4, sort_keys=True)

def main():
    '''
        Main function
    '''

    # Check if a url was given as an argument
    if len(sys.argv) < 2:
        print("Please provide a valid url:\n\t%s \"https://someurl.com/test?id=1\"" % sys.argv[0] \
            + "\nIn order to print the FULL response, please run "\
            + "\n\t%s \"https://someurl.com/test?id=1\"" % sys.argv[0])
        sys.exit()
    full = False
    if len(sys.argv) == 3:
        if sys.argv[2] == "full":
            full = True
    # Check if the given url is a valid url
    arg_url = re.findall(URL_REGEX_PATTERN, sys.argv[1])
    if len(arg_url) == 0:
        print("Please provide a valid URL!")
        sys.exit()
    else:
        url = arg_url[0][0]

    vt_key = get_vt_api_key()
    vt_key_status = check_vt_key(vt_key)
    if vt_key_status != "verified":
        print("Error: %s" % vt_key_status)
        sys.exit()
    headers = {'x-apikey': vt_key}
    url_base64 = get_url_base64(url)
    session = requests.Session()
    # Check if the URL has been analysed already by submitting it's base64
    res = session.get(BASE_URL + '/urls/' + url_base64, headers=headers)
    url_id = ""
    data = {'url': url}
    if 'error' not in res.json() and len(res.json()['data']) > 0:
        epoch_time = calendar.timegm(time.gmtime())
        # If the last analysis was more than 24 hours ago, reanalyse
        if int((res.json()['data']['attributes']['last_analysis_date']) + 86400) < epoch_time:
            res = session.post(BASE_URL + '/urls', headers=headers, data=data)
            url_id = res.json()['data']['id']
        else:
            print("URL Detections:\n----------------")
            if full is False:
                print("URL STATS:")
                print(pretty_json(res.json()['data']['attributes']['last_analysis_stats']))
                print("URL CATEGORIES:")
                print(pretty_json(res.json()['data']['attributes']['categories']))
            else:
                print(pretty_json(res.json()))
            sys.exit()

    # If the hash wasn't found or it was analysed more than 24 hours ago
    if url_id == "":
        res = session.post(BASE_URL + "/urls", data=data, headers=headers)
        url_id = res.json()['data']['id']
    res = session.get(BASE_URL + "/analyses/" + url_id, headers=headers)
    status = res.json()['data']['attributes']['status']
    # A url analysing can take some time. Print the output only when it's ready.
    while status == 'queued':
        print("Waiting for url status, please wait...")
        time.sleep(10)
        res = session.get(BASE_URL + "/analyses/" + url_id, headers=headers)
        status = res.json()['data']['attributes']['status']
    res = session.get(BASE_URL + '/urls/' + url_base64, headers=headers)
    print("URL Detections:\n----------------")
    if full is False:
        print("URL STATS:")
        print(pretty_json(res.json()['data']['attributes']['last_analysis_stats']))
        print("URL CATEGORIES:")
        print(pretty_json(res.json()['data']['attributes']['categories']))
    else:
        print(pretty_json(res.json()))

if __name__ == '__main__':
    main()
