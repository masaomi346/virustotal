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

def scan():
    files = []
    path = "/opt/dionaea/var/lib/dionaea/binaries/"
    for f in os.listdir(path):
        if os.path.isfile(os.path.join(path,f)) : files.append(f)
    if len(files) == 0 : return "No Malware"
    output = "{}\n\n".format(len(files))
    for hash in files:
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {"resource": hash, "apikey": "APIKEY"}
        data = urllib.parse.urlencode(params)
        req = urllib.request.Request(url,data.encode("ascii"))
        res = urllib.request.urlopen(req).read().decode("utf-8")
        res = [json.loads(res) for s in res if s != ""]
        if len(res) != 0 and res[-1].get("response_code") == 1 :
            cmd = "file " + path + "{}".format(hash)
            result = str(subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE).communicate()[0])
            output += "Type:{0}\nHash(SHA256):{1}\nTotal:{2}\nDetect:{3}\nURL:{4}\n\n".format(result.replace("/opt/dionaea/var/lib/dionaea/binaries/{}".format(hash),""),res[-1].get("sha256"),res[-1].get("total"),res[-1].get("positives"),res[-1].get("permalink"))
    return output

def send(result):
    cmd = "curl -X POST -H 'Content-type: application/json' --data {} https://hooks.slack.com/services/TOKEN"
    cmd = cmd.format(json.dumps('{\"text\":\"' + result + '\"}'))
    subprocess.call(shlex.split(cmd))

result = scan()
send(result)