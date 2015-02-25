"""
  ___       _
 / _ \  ___| |_ ___  _ __  _   _ ___
| | | |/ __| __/ _ \| '_ \| | | / __|
| |_| | (__| || (_) | |_) | |_| \__ \
 \___/ \___|\__\___/| .__/ \__,_|___/
                    |_|

<HSC-Herve Schauer Consultants 2015>

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

"""

from params import att_types, dictpath, slavenode
import os
import string
import re


slavehome = slavenode["vars"]["HOME"]


def replace_multiple(string, replace):
    re_sub = re.compile(re.escape('|'.join(replace.keys())))
    return re_sub.sub(lambda m: replace[m.group(0)], string)


def escape_all(string):
    string = string.replace("\"", "\\\"")
    string = string.replace("!", "\\!")
    string = string.replace("&", "\\&")
    string = string.replace("'", "\\'")
    string = string.replace("(", "\\(")
    string = string.replace(")", "\\)")
    string = string.replace(";", "\\;")
    string = string.replace("`", "\\`")
    string = string.replace("|", "\\|")
    string = string.replace("?", "??")
    return string


def checkFile(pPath):
    if not os.path.isfile(pPath):
        parent = os.path.dirname(pPath)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        open(pPath, "w").close()


def is_example_att(job):
    return ("pilou" in job)


def is_mask(mask):
    l = len(mask)
    if not l:
        return False
    START, CHARSET, CUSTINIT, CUST, CUSTEND, STRINIT, STR, STREND = range(8)
    state = START
    custs = set()
    for i in range(l):
        if state == START:
            if mask[i] == "?":
                state = CHARSET
            elif mask[i] == "[":
                state = CUSTINIT
            elif mask[i] == "<":
                state = STRINIT
            else:
                print "Unknown init '%s'" %(mask[i])
                return False
        elif state == CHARSET:
            if mask[i] in ["d", "l", "u", "s", "a"]:
                state = START
            else:
                print "Unknown charset '%s'" %(mask[i])
                return False
        elif state == CUSTINIT:
            if mask[i] == "/":
                state = CUST
            else:
                print "Cust init failed"
                return False
        elif state == CUST:
            if mask[i] == "/":
                state = CUSTEND
        elif state == CUSTEND:
            if mask[i] == "]":
                state = START
            else:
                state = CUST
        elif state == STRINIT:
            if mask[i] == "/":
                state = STR
            else:
                print "String init failed"
                return False
        elif state == STR:
            if mask[i] == "/":
                state = STREND
        elif state == STREND:
            if mask[i] == ">":
                state = START
            else:
                state = STR
    if state == START and len(custs) < 4:
        return True
    else:
        err = (state==START and "Ending error") or "Too many custom masks"
        print err
        return False


def is_dictionary(name):
    dicts = []
    checkFile("%s/dictionaries" %(dictpath))
    with open("%s/dictionaries" %(dictpath), "r") as f:
        for line in f:
            dicts.append(line.strip("\n"))
    return (name in dicts)


jobParser = {"mask": is_mask, "dictionary": is_dictionary,
                "toggle_case": is_dictionary}


def format(hash, type, program):
    regex = hashtypes[type][program]["regex"]
    match = re.search(regex, hash)
    if match:
        #print match.group(1)
        return match.group(1)


def attack(program, type, vars):
    att = commands[att_types[type]][program]
    cmd = att(vars)
    return cmd


def apply(string, vars):
    result = string
    for key in vars.keys():
        result = result.replace("$%s" %key, vars[key])
    return result

# ================================= ATTACKS ================================= #
# Hashcat mask attack
hm_cmd = "$PROGS/hashcat/hashcat-cli32.bin -m $HASHTYPE -a $ATT "
hm_cmd += "--pw-min=$PWMIN $CUSTS $HOME/tmp/hashes $JOB"


def make_mask(mask, d = string.digits,
                    l = string.lowercase,
                    u = string.uppercase,
                    s = string.punctuation,
                    a = string.printable[0:-6]):
    """
    Creates a mask readable by Hashcat.
        - 0123456789 becomes ?d
        - abcdefghijklmnopqrstuvwxyz becomes ?l
        - etc.
    """
    m_list = mask.split("||")
    #print "m_list:", m_list
    special = ""
    r_mask = ""
    specd = dict()
    e_mask = {d: "?d",
                l: "?l",
                u: "?u",
                s: "?s",
                a: "?a"}
    for em in m_list:
        #r_mask += re.sub(r"</(.*?)/>", r"\1", em)
        if em in e_mask.keys():
            r_mask += e_mask[em]
        elif re.search(r"</.*/>", em):
            #r_mask += em.replace("</", "").replace("/>", "")
            r_mask += replace_multiple(em, {"</": "", "/>": ""})
        elif len(em) == 1:
            r_mask += em
        else:
            if em in specd.keys():
                r_mask += "?" + specd[em]
            else:
                specd[em] = "%d" %(len(specd) + 1)
                r_mask += "?" + specd[em]
    return r_mask, special, specd


def hashcat_mask(vars):
    mask = vars["JOB"]
    vars["ATT"] = "3"
    d, l = vars["d"], vars["l"]
    u, s, a = vars["u"], vars["s"], vars["a"]
    #paramg = mask.replace(a, "?a").replace(d, "?d").replace(l, "?l")
    #paramg = paramg.replace(s, "?s").replace(u, "?u").replace("||", " ")
    replace = {a: "?a", d: "?d", l: "?l", s: "?s", u: "?u", "||": " "}
    paramg = replace_multiple(mask, replace)
    pw_min = str(len(paramg.split("||")))
    vars["JOB"], spec, specd = make_mask(mask, d, l, u, s, a)
    custs = ""
    for a in specd.keys():
        custs += "-%s %s " %(specd[a], escape_all(a))
    if spec:
        spec = escape_all(spec)
        custs += "-1 %s " %(spec)
    vars["CUSTS"] = custs
    vars["PWMIN"] = pw_min
    applied_cmd = apply(hm_cmd, vars)
    return applied_cmd

# Hashcat dictionary attacks
hd_cmd = "$PROGS/hashcat/hashcat-cli32.bin -m $HASHTYPE -a 0 "
hd_cmd += "$HOME/tmp/hashes $HOME/tmp/dictionary"

ht_cmd = "$PROGS/hashcat/hashcat-cli32.bin -m $HASHTYPE -a 5 "
ht_cmd += "--table-file $HOME/tables/toggle_case.table $HOME/tmp/hashes "
ht_cmd += "$HOME/tmp/dictionary"


def hashcat_dictionary(vars):
    # Apply variables to the command
    applied_cmd = apply(hd_cmd, vars)
    # And return the command to perform
    return applied_cmd


def hashcat_togglecase(vars):
    # Apply variables to the command
    applied_cmd = apply(ht_cmd, vars)
    # And return the command to perform
    return applied_cmd


def make_hashcat_mask(job):
    return job


def make_hashcat_dictionary(job):
    if os.path.exists("%s/tmp/dictionary" %slavehome):
        os.remove("%s/tmp/dictionary" %slavehome)
    with open("%s/tmp/dictionary" %slavehome, "a") as f:
        for word in job:
            # TODO: Solve problem
            try:
                f.write(word + "\n")
            except UnicodeEncodeError:
                pass
    return "%s/tmp/dictionary" %slavehome


makeJob = {"mask": {"hashcat": make_hashcat_mask},
            "dictionary": {"hashcat": make_hashcat_dictionary},
            "toggle_case": {"hashcat": make_hashcat_dictionary}}

commands = {"mask": {"hashcat": hashcat_mask},
            "dictionary": {"hashcat": hashcat_dictionary},
            "toggle_case": {"hashcat": hashcat_togglecase}}

hashtypes = {"MD5":
                {"hashcat":
                    {"id": "0",
                    "regex": r"^([a-fA-F0-9]{32})"}},
            "MD5 (Unix)":
                {"hashcat":
                    {"id": "500",
                    "regex": r"^[^:]+:(\$1\$[a-zA-Z0-9\./=]{8}\$[a-zA-Z0-9\./=]{22}).*$"}},
            "SHA256 (Unix)":
                {"hashcat":
                    {"id": "7400",
                    "regex": r"^[^:]+:(\$1\$[a-zA-Z0-9\./=]{16}\$[a-zA-Z0-9\./=]{43}).*$"}},
            "SHA512 (Unix)":
                {"hashcat":
                    {"id": "1800",
                    "regex": r"^[^:]+:(\$1\$[a-zA-Z0-9\./=]{16}\$[a-zA-Z0-9\./=]{86}).*$"}},
            "Blowfish (OpenBSD)":
                {"hashcat":
                    {"id": "3200",
                    "regex": r"^[^:]+:(\$2a\$05\$[a-zA-Z0-9\./=]{53}).*$"}},
            "DES (Unix)":
                {"hashcat":
                    {"id": "1500",
                    "regex": r"^[^:]+:([a-zA-Z0-9\./=]{13}).*$"}},
            "Lotus 5":
                {"hashcat":
                    {"id": "8600",
                    "regex": r"^[^:]+:([a-fA-F0-9]{32}).*$"}},
            "M$ Cache 2":
                {"hashcat":
                    {"id": "3200",
                    "regex": r"^[^:]+:(\$DCC2\$10240#[^:#]+#[a-fA-F0-9]{32}).*$"}},
            "NTLM (Windows)":
                {"hashcat":
                    {"id": "1000",
                    "regex": r"^[^:]+:[0-9]+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):.*$"}}}
