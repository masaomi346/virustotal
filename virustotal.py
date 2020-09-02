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

def analyze():
    files = []
    result = ""
    try:
        path = "/opt/dionaea/var/lib/dionaea/binaries/"
        for f in os.listdir(path):
            if os.path.isfile(os.path.join(path,f)) : files.append(f)
        if len(files) == 0 :
            result = "No Malware"
            send(result)
            return
        else:
            result = "Numbers:{}\n\n".format(len(files))
            send(result)
        for hash in files:
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            params = {"resource": hash, "apikey": "APIKEY"}
            data = urllib.parse.urlencode(params)
            req = urllib.request.Request(url,data.encode("ascii"))
            res = urllib.request.urlopen(req).read().decode("utf-8")
            res = [json.loads(res) for s in res if s != ""]
            cmd = "file " + path + "{}".format(hash)
            cmd = str(subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE).communicate()[0])
            result = "Type:{0}\nHash:{1}\nTotal:{2}\nDetect:{3}\nURL:{4}\n\n".format(cmd.replace(path + "{}".format(hash),""),hash,res[-1].get("total"),res[-1].get("positives"),res[-1].get("permalink"))
            send(result)
            time.sleep(1)
    except Exception as e:
        send(e)

def send(result):
    push = "curl -X POST -H 'Content-type: application/json' --data {} https://hooks.slack.com/services/TOKEN"
    if type(result) is str:
        push = push.format(json.dumps('{\"text\":\"' + result + '\"}'))
        subprocess.call(shlex.split(push))

result = analyze()
send(result)