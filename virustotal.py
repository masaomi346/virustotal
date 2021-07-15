#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import urllib
import urllib.parse
import urllib.request
import urllib.response
import os
import subprocess
import shlex

def analyze():
    files = []
    path = "/opt/dionaea/var/lib/dionaea/binaries/"
    for f in os.listdir(path):
        if os.path.isfile(os.path.join(path,f)) : files.append(str(f))
    if len(files) == 0 :
        result.append("No Malware")
        return result
    result.append("Numbers:{}\n\n".format(len(files)))
    for hash in files:
        url = "https://www.virustotal.com/api/v3/files/" + hash
        key = {"x-apikey": "APIKey"}
        req = urllib.request.Request(url,headers=key)
        try:
            cmd = "file " + path + "{}".format(hash)
            cmd = str(subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE).communicate()[0])
            with urllib.request.urlopen(req) as res:
                res = json.loads(res.read().decode("utf-8"))
                result.append("Type:{0}\nHash:{1}\nMalicious:{2}\nSuspicious:{3}\nUndetected:{4}\nURL: https://www.virustotal.com/gui/file/{5}\n\n".format(cmd.replace(path + "{}".format(hash),""),hash,res["data"]["attributes"]["last_analysis_stats"].get("malicious"),res["data"]["attributes"]["last_analysis_stats"].get("suspicious"),res["data"]["attributes"]["last_analysis_stats"].get("undetected"),res["data"].get("id")))
        except:
            result.append("Maybe it's not uploaded.\nMessage:{}".format(sys.exc_info()))

def send(result):
    for data in result:
        if type(data) is str:
            push = "curl -X POST -H 'Content-type: application/json' --data {} https://hooks.slack.com/services/TOKEN"
            push = push.format(json.dumps('{\"text\":\"' + data + '\"}'))
            subprocess.call(shlex.split(push))

result = []
analyze()
send(result)