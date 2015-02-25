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

import string
import params
import os
import math
import Queue
from params import charsets
from collections import deque

wordsbynodedict = 400000
wordsbynodemask = 800000000
home = params.master_vars["HOME"]
api_home = params.api_vars["HOME"]


def chunkify(type, job, id):
    return typeToChunker[type](job, id)

#-----------------------------------------------------------------------------#
# Divide a mask into chunks

def mask(mask, id):
    """
    Creates jobs for a given mask and adds them to jobs dictionary.
    """
    d, l = charsets["d"], charsets["l"]
    u, s, a = charsets["u"], charsets["s"], charsets["a"]
    m = MaskDivider(d, l, u, s, a)
    # Divide mask into chunks
    mask = m.divide(mask)
    # Create jobs from mask chunks
    jobs = maskJobs(mask)
    return jobs


def maskJobs(mask):
    """
    maskJobs: mask -> jobs
    """
    s = mask.pop()
    jobs, l = deque(), len(s)
    for i in range(0, l):
        jobs.append(s.pop())
    while mask:
        s = mask.pop()
        nl = len(s)
        for i in range(0, l):
            t = jobs.popleft()
            for u in s:
                jobs.append(u + "||" + t)
        l = l*nl
    return jobs


class MaskDivider:
    """
    MaskDivider class is used to divide Hashcat masks into pieces.
    """

    def __init__(self, d = string.digits,
                    l = string.lowercase,
                    u = string.uppercase,
                    s = string.punctuation,
                    a = string.printable[0:len(string.printable) - 6]):
        self.d = d
        self.l = l
        self.u = u
        self.s = s
        self.a = a

    def cardinal(self, c_string):
        """
        Returns the number of different passwords that can be generated by a
        given mask.
        """
        card = 1
        for c in c_string:
            card *= len(c)
        return card

    def nb_div(self, c_string):
        """
        Returns the number of times a mask has to be divided into two parts to
        match wordsbynode.
        """
        card = self.cardinal(c_string)
        res = int(math.log(card, 2) - math.log(wordsbynodemask, 2)) + 1
        return min(res, 15)

    def divide_elem(self, elem, nb):
        """
        Divides elem into 2^nb elements. If len(elem) < 2^nb it divides it into
        len(elem) parts. Returns (elems, rem), elems is a list of all parts and
        rem is the remaining number of divisions (rem = 0 if len(elem) > 2^nb).
        """
        if pow(2, nb) < len(elem):
            e_list = []
            queue = Queue.Queue()
            queue.put(len(elem))
            for i in range(0, nb):
                for j in range(0, int(pow(2, i))):
                    val = queue.get()
                    queue.put(int((val+1)/2))
                    queue.put(int(val/2))
            ind1 = 0
            ind2 = queue.get()
            while not queue.empty():
                e_list.append(elem[ind1:ind2])
                ind1, ind2 = ind2, ind2 + queue.get()
            e_list.append(elem[ind1:ind2])
            return (e_list, 0)
        else:
            return (list(elem), nb - int(math.log(len(elem), 2)))

    def divide(self, mask):
        """
        Combines divide_elem on every element with a view to divide a whole
        mask.
        """
        s_list = []
        c_string = []
        accu = ""
        is_spe = False
        is_str = False
        count = 0
        e_char = {"d": self.d,
                    "l": self.l,
                    "u": self.u,
                    "s": self.s,
                    "a": self.a}
        for c in mask:
            count += 1
            if accu == "<" and c == "/":
                # print count, "Initialisation of string"
                is_str = True
            if is_str:
                # print count, "Writing string..."
                accu += c
                if len(accu) > 4 and accu[len(accu)-2:len(accu)] == "/>":
                    # print count, "End of string"
                    for d in accu[2:-2]:
                        c_string.append(d)
                    accu = ""
                    is_str = False
            elif len(accu) > 4 and accu[0:2] + accu[-1] == "[//" and c == "]":
                # print count, "End of custom mask"
                accu += c
                c_string.append(accu[2:-2])
                accu = ""
            elif len(accu) > 1 and accu[0:1] == "[/":
                # print count, "Writing custom mask..."
                accu += c
            elif accu == "[" and c == "/":
                # print count, "Initialisation of custom mask finished"
                accu += c
            elif c == "[":
                # print count, "Initialising custom mask..."
                if len(accu) > 0:
                    c_string.append(accu)
                accu = c
            elif c == "?":
                # print count, "Writing special character"
                if len(accu) > 0:
                    c_string.append(accu)
                    accu = ""
                is_spe = True
            else:
                if is_spe:
                    # print count, "Special character written"
                    is_spe = False
                    if c in e_char.keys():
                        c_string.append(e_char[c])
                    else:
                        # print count, "Foo"
                        accu = accu + c
                else:
                    # print count, "Foo"
                    accu = accu + c
        if accu:
            c_string.append(accu)
        # print mask, c_string
        nb = self.nb_div(c_string)
        while nb:
            e_list, nb = self.divide_elem(c_string.pop(), nb)
            s_list.append(e_list)
        while c_string:
            s_list.append([c_string.pop()])
        s_list.reverse()
        return s_list


#-----------------------------------------------------------------------------#
# Divide a dictionary into chunks

def dictionary(dictionary, id):
    """
    Creates jobs for a dictionary attack.
    """
    path = "%s/%s.txt" %(params.dictpath, dictionary)
    tmp = os.listdir("%s/tmp/%s" %(home, id))
    tmp.remove("hashes")
    l = [int(a.split("part")[1]) for a in tmp] + [-1]
    offset = max(l) + 1
    with open(path, "r") as file:
        # Make chunks from a dictionary
        jobs = dictToChunks(file, id, offset)
    return jobs


def dictToChunks(file, id, offset):
    """
    Takes a dictionary and creates chunks with it.
    """
    jobs = []
    count = 0
    curdict = ""
    if not os.path.exists("%s/tmp/%s" %(home, id)):
        os.mkdir("%s/tmp/%s" %(home, id))
    for curLine in file.xreadlines():
        curdict+= "\n" + curLine.decode('latin-1').encode('utf-8')
        count+=1
        if count == wordsbynodedict:
            num = len(jobs) + offset
            path = "%s/tmp/%s/part%d" %(home, id, num)
            jobs.append(path)
            createChunk(path, curdict)
            curdict = ""
            count = 0
    if curdict:
        num = len(jobs) + offset
        path = "%s/tmp/%s/part%d" %(home, id, num)
        jobs.append(path)
        createChunk(path, curdict)
    return jobs


def createChunk(path, words):
    """
    Same as createDict but creates a chunk of dictionary that will be used by
    a slavenode.
    """
    with open(path, "a+") as c:
        c.write(words)

#-----------------------------------------------------------------------------#

def get_mask(chunk):
    return chunk


def get_dictionary(chunk):
    words = []
    with open(chunk, "r") as f:
        for line in f:
            words.append(line.strip("\n"))
    return words


def save_mask(chunk, dir):
    return chunk


def save_dictionary(chunk, path):
    with open(path, "a") as f:
        for word in chunk:
            try:
                f.write(word + "\n")
            except UnicodeEncodeError:
                pass
    return path


typeToChunker = {"mask": mask, "dictionary": dictionary,
                    "toggle_case": dictionary}
getChunk = {"mask": get_mask, "dictionary": get_dictionary,
            "toggle_case": get_dictionary}
saveChunk = {"mask": save_mask, "dictionary": save_dictionary,
            "toggle_case": save_dictionary}