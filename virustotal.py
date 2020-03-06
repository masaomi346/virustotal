#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import urllib
import urllib.parse
import urllib.request
import urllib.response
import os
import time
import subprocess
import shlex
import schedule

def scan():
    files = []
    analysis = []
    path = "/opt/dionaea/var/lib/dionaea/binaries/"
    for f in os.listdir(path):
        if os.path.isfile(os.path.join(path,f)) : files.append(f)
    if len(files) == 0 :
        analysis.append("No Malware")
        return analysis
    analysis.append("Numbers:{}\n\n".format(len(files)))
    for hash in files:
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {"resource": hash, "apikey": "APIKEY"}
        data = urllib.parse.urlencode(params)
        req = urllib.request.Request(url,data.encode("ascii"))
        res = urllib.request.urlopen(req).read().decode("utf-8")
        res = [json.loads(res) for s in res if s != ""]
        cmd = "file " + path + "{}".format(hash)
        result = str(subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE).communicate()[0])
        analysis.append("Type:{0}\nHash:{1}\nTotal:{2}\nDetect:{3}\nURL:{4}\n\n".format(result.replace("/opt/dionaea/var/lib/dionaea/binaries/{}".format(hash),""),hash,res[-1].get("total"),res[-1].get("positives"),res[-1].get("permalink")))
    return send(analysis)

def send(analysis):
    for i in range(len(analysis)):
        cmd = "curl -X POST -H 'Content-type: application/json' --data {} https://hooks.slack.com/services/TOKEN"
        cmd = cmd.format(json.dumps('{\"text\":\"' + analysis[i] + '\"}'))
        subprocess.call(shlex.split(cmd))

schedule.every().day.at("20:00").do(scan)
while(True):
    schedule.run_pending()
    time.sleep(1)