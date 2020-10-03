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
import traceback

def analyze():
    files = []
    try:
        path = "/opt/dionaea/var/lib/dionaea/binaries/"
        for f in os.listdir(path):
            if os.path.isfile(os.path.join(path,f)) : files.append(str(f))
        if len(files) == 0 :
            result.append("No Malware")
            return result
        result.append("Numbers:{}\n\n".format(len(files)))
        for hash in files:
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            params = {"resource": hash, "apikey": "APIKEY"}
            post = urllib.parse.urlencode(params)
            req = urllib.request.Request(url,post.encode("ascii"))
            res = urllib.request.urlopen(req).read().decode("utf-8")
            res = [json.loads(res) for s in res if s != ""]
            cmd = "file " + path + "{}".format(hash)
            cmd = str(subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE).communicate()[0])
            result.append("Type:{0}\nHash:{1}\nTotal:{2}\nDetect:{3}\nURL:{4}\n\n".format(cmd.replace("/opt/dionaea/var/lib/dionaea/binaries/{}".format(hash),""),hash,res[-1].get("total"),res[-1].get("positives"),res[-1].get("permalink")))
    except:
        result.append(traceback.print_exc())
    return result

def send(result):
    for data in result:
        if type(data) is str:
            push = "curl -X POST -H 'Content-type: application/json' --data {} https://hooks.slack.com/services/TOKEN"
            push = push.format(json.dumps('{\"text\":\"' + data + '\"}'))
            subprocess.call(shlex.split(push))

result = []
analyze()
send(getdata)