from _socket import timeout

import requests
import json
import time

import vt

import perturbation as p
import lief
import random
import subprocess
import urllib3 as urllib

apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)
vt_api_invoke_count = 0


def send_to_sandbox(fname):
    sburl = "http://localhost:8090/tasks/create/file"
    data = {'timeout': '30'}
    with open(fname, 'rb') as sample:
        files = {"file": (fname, sample)}
        header = {"Authorization": "Bearer A1f2ICXgK8FIL8EuB1WArA"}
        r = requests.post(sburl, data=data, files=files, headers=header)

    if r.status_code == 200:
        return r.json()

    return False


def status(taskid):
    spurl = "http://localhost:8090/tasks/view/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer A1f2ICXgK8FIL8EuB1WArA"}

    r = requests.get(spurl + str(taskid), headers=header)
    return r.json()


def get_cuckoo_report(fname):
    rpurl = "http://localhost:8090/tasks/report/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer A1f2ICXgK8FIL8EuB1WArA"}

    taskid = send_to_sandbox(fname)["task_id"]

    while status(taskid)['task']['status'] != "reported":
        time.sleep(10)

    r = requests.get(rpurl + str(taskid), headers=header)

    #print(r.json())

    return r.json()


def checkVtApiReadiness(origin):
    if origin.vt_api_count >= 3:
        time.sleep(60)
        origin.vt_api_count = 0


def send_v2_vt_scan(fpath, apikey, origin):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': ('myfile.exe', open(fpath, 'rb'))}
    try:
        response = requests.post(url, files=files, params=params)
    except Exception as e:
        print('---catch timeout --')
        print(e)
        time.sleep(90)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return send_v2_vt_scan(fpath, apikeylist[origin.vt_api_count], origin)
    print(response.status_code)

    if response.status_code == 200:
        return response.json()["md5"]
    else:
        time.sleep(90)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return send_v2_vt_scan(fpath, apikeylist[origin.vt_api_count], origin)
    # pass


def get_v2_vt_report(hashvalue, apikey, origin):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': hashvalue}
    try:
        response = requests.get(url, params=params)
    except Exception as e:
        print('---catch timeout --')
        print(e)
        time.sleep(90)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return get_v2_vt_report(hashvalue, apikeylist[origin.vt_api_count], origin)

    # status = response.json()["response_code"]
    print(response.status_code)

    if response.status_code == 200:
        return response.json()
    else:
        time.sleep(90)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return get_v2_vt_report(hashvalue, apikeylist[origin.vt_api_count], origin)


def vt_v2_analysis(filehash, original):
    random.seed(None)
    i = random.randrange(0, apilen)
    # print (apikeylist[i])
    # scan = send_vt_scan(fpath,apikeylist[i])
    # filehash = scan["md5"]
    while True:
        # i = (i+1)%apilen
        original.vt_api_count = (original.vt_api_count + 1) % apilen
        vt_report = get_v2_vt_report(filehash, apikeylist[original.vt_api_count], original)
        print('---vt report---')
        print(vt_report)
        if vt_report["response_code"] == 1:
            vt_result = vt_report["positives"] / vt_report["total"]
            break
        time.sleep(10)

    return vt_result, vt_report


def send_v3_vt_scan(fpath, apikey, origin):
    # url = 'https://www.virustotal.com/api/v3/files'
    # headers = {'accept': 'application/json', 'x-apikey': apikey}
    # files = {'file': ('myfile.exe', open(fpath, 'rb'))}
    # try:
    #     response = requests.post(url, files=files, headers=headers)
    # except Exception as e:
    #     print('---catch timeout --')
    #     print(e)
    #     time.sleep(90)
    #     origin.vt_api_count = (origin.vt_api_count + 1) % apilen
    #     return send_v3_vt_scan(fpath, apikeylist[origin.vt_api_count], origin)
    # print(response.status_code)
    #
    # if response.status_code == 200:
    #     return response.json()["data"]["id"]
    # else:
    #     time.sleep(90)
    #     origin.vt_api_count = (origin.vt_api_count + 1) % apilen
    #     return send_v3_vt_scan(fpath, apikeylist[origin.vt_api_count], origin)
    # pass
    vt_client = vt.Client(apikeylist[0])
    with open(fpath, "rb") as f:
        analysis = vt_client.scan_file(f)
        vt_client.close()
        return analysis.id

def get_v3_vt_report(analysisId, apikey, origin):
    # url = 'https://www.virustotal.com/api/v3/analyses/' + analysisId
    # headers = {'accept': 'application/json', 'x-apikey': apikey}
    # try:
    #     response = requests.get(url, headers=headers)
    # except Exception as e:
    #     print('---catch timeout --')
    #     print(e)
    #     time.sleep(90)
    #     origin.vt_api_count = (origin.vt_api_count + 1) % apilen
    #     return get_v3_vt_report(analysisId, apikeylist[origin.vt_api_count], origin)
    #
    # # status = response.json()["response_code"]
    # print(response.status_code)
    #
    # if response.status_code == 200:
    #     return response.json()
    # else:
    #     time.sleep(90)
    #     origin.vt_api_count = (origin.vt_api_count + 1) % apilen
    #     return get_v3_vt_report(analysisId, apikeylist[origin.vt_api_count], origin)
    vt_client = vt.Client(apikeylist[0])
    while True:
        report = vt_client.get_object("/analyses/{}", analysisId)
        if report.status == "completed":
            vt_client.close()
            return report
        time.sleep(30)


def vt_v3_analysis(filehash, original):
    random.seed(None)
    vt_report = get_v3_vt_report(filehash, apikeylist[original.vt_api_count], original)
    vt_result = vt_report.stats["malicious"] / (vt_report.stats['undetected'] + vt_report.stats["malicious"])
    return vt_result, vt_report.results



def creat_v2_jotti_scan_token( apikey, origin):
    url = 'https://virusscan.jotti.org/api/filescanjob/v2/createscantoken'
    headers = {'accept': 'application/json', 'Content-Type': 'multipart/form-data',
               'Authorization': 'Key nA5BxHYJU77V16Yy'}
    try:
        response = requests.post(url, headers=headers)
    except Exception as e:
        print('---catch timeout --')
        print(e)
        time.sleep(30)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return creat_v2_jotti_scan_token()
    print(response.status_code)

    if response.status_code == 200:
        return response.json()["scanToken"]
    else:
        time.sleep(30)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return creat_v2_jotti_scan_token()
    # pass

def create_v2_jotti_scan_job(fpath,scantoken, apikey, origin):
    url = 'https://virusscan.jotti.org/api/filescanjob/v2/createjob'
    headers = {'accept': '*/*',
               'Authorization': 'Key nA5BxHYJU77V16Yy'}
    files = {'file': ('myfile.exe', open(fpath, 'rb'), 'application/octet-stream')}
    form_data = {'scanToken': scantoken}

    try:
        response = requests.post(url, files=files, data=form_data, headers=headers)
    except Exception as e:
        print('---catch timeout --')
        print(e)
        time.sleep(30)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return create_v2_jotti_scan_job(fpath, scantoken)
    #print(response.status_code)

    if response.status_code == 201:
        return response.json()["fileScanJobId"]
    else:
        time.sleep(30)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return create_v2_jotti_scan_job(fpath, scantoken)
    # pass

def send_v2_jotti_scan(fpath, apikey, origin):
    if origin.vt_api_count >= 100:
        time.sleep(300)
    else:
        time.sleep(2)
    scanToken = creat_v2_jotti_scan_token(apikey, origin)
    scanJobId = create_v2_jotti_scan_job(fpath, scanToken,apikey, origin)
    return scanJobId

def get_v2_jotti_report(scanJobId,apikey, origin):
    if origin.vt_api_count >= 100:
        time.sleep(300)
    else:
        time.sleep(20)
    url = 'https://virusscan.jotti.org/api/filescanjob/v2/getjobstatus/' + scanJobId
    headers = {'accept': 'application/json', 'Content-Type': 'multipart/form-data',
               'Authorization': 'Key nA5BxHYJU77V16Yy'}
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        print('---catch timeout --')
        print(e)
        time.sleep(30)
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return get_v2_jotti_report(scanJobId, apikey, origin)
    #print(response.status_code)

    if response.status_code == 200:
        if response.json()['scanJob']['finishedOn'] == None:# Scan result is not ready
            return get_v2_jotti_report(scanJobId, apikey, origin)
        else:# scan result is ready
            return response.json()
    else:# error accessing API
        origin.vt_api_count = (origin.vt_api_count + 1) % apilen
        return get_v2_jotti_report(scanJobId, apikey, origin)
    # pass


def jotti_v2_analysis(scanJobId, original):
    original.vt_api_count = (original.vt_api_count + 1) % apilen
    jotti_report = get_v2_jotti_report(scanJobId, apikeylist[original.vt_api_count], original)
    #print('---vt report---')
    #print(jotti_report)
    jotti_result = jotti_report["scanJob"]["scannersDetected"] / jotti_report["scanJob"]["scannersRun"]
    return jotti_result, jotti_report


def get_malware_analysis(scanJobId, original):
    #return jotti_v2_analysis(scanJobId, original)
    return vt_v3_analysis(scanJobId, original)

def send_malware_scan(fpath, apikey, origin):
    #return send_v2_jotti_scan(fpath, apikey, origin)
    return send_v3_vt_scan(fpath, apikey, origin)

def check_sig_set(signatures):
    sigs = []
    for sig in signatures:

        if sig["severity"] > 1:
            sigs.append(sig["description"])

    return set(sigs)


def check_key_instructions():
    pass


# origin = json report, target = filename
def func_check(origin_sig, target):
    target_sig = get_cuckoo_report(target)["signatures"]

    osig = check_sig_set(origin_sig)
    tsig = check_sig_set(target_sig)

    total = osig | tsig
    match = osig & tsig

    if len(match) / len(total) > 0.6:
        return True
    else:
        return False
