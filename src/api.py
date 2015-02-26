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

from twisted.protocols.basic import LineReceiver
from twisted.internet import protocol, reactor
from collections import deque
from params import api as config
from chunkify import getChunk, saveChunk
from attacks import jobParser, commands, hashtypes
from params import charsets, secondarynode, masternode
import time
import errno
import shutil
import json
import urlparse
import urllib2
import os
import re
import optparse
import logs
import backupdb
#import zlib
import matrices

# API's home directory. Contains tmp directory (used for temporary files such
# as chunks of dictionaries), policy directory (containing attack policies),
# results directory (for storing found passwords) and api.log file.
home = config["vars"]["HOME"]

# Listening interface and port
HOST = config["host"]
PORT = config["port"]

OCTOPUS = """
  ___       _
 / _ \\  ___| |_ ___  _ __  _   _ ___
| | | |/ __| __/ _ \\| '_ \\| | | / __|
| |_| | (__| || (_) | |_) | |_| \\__ \\
 \\___/ \\___|\\__\\___/| .__/ \\__,_|___/
                    |_|
"""
print OCTOPUS
print "Started Octopus"


def replace_multiple(string, replace):
    re_sub = re.compile('|'.join(replace.keys()))
    return re_sub.sub(lambda m: replace[m.group(0)], string)


def checkFile(pPath):
    if not os.path.isfile(pPath):
        parent = os.path.dirname(pPath)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        open(pPath, "w").close()

# Temporary directory
tmpdir = "%s/tmp" %(home)
# Policies directory
polpath = "%s/policies" %(home)
# Save in an array all policies paths
checkFile("%s/list" %(polpath))
with open("%s/list" %(polpath), "r") as f:
    policies = [policy.strip("\n") for policy in f.xreadlines()]

# Log file, used for logging connections and messages sent by and to API
logger = logs.Logger("%s/api.log" %(home), reactor)


def parse_args():
    """
    Arguments parser. User can provide a backup database.
    """
    usage = """usage: %prog [options] hashfile"""

    parser = optparse.OptionParser(usage)

    help = "Backup file"
    parser.add_option("-b", "--backup", help = help)
    help = "Debug mode"
    parser.add_option("-d", "--debug", action = "store_true", help = help)

    options, args = parser.parse_args()
    return options


options = parse_args()

debug = options.debug

# Backup file path
backupath = options.backup


def httprequest(data):
    """
    Embeds data into a well-formed HTTP request.
    """
    #data = zlib.compress(data)
    if debug:
        print "httprequest(%s)" %(data)
    request = "GET /?cmd=%s HTTP/1.1\r\n" %urllib2.quote(data)
    request += "User-Agent: Octopus"
    return request


def httpresponse(data):
    """
    Embeds data into a well-formed HTTP response to be sent to a client
    (typically via the API).
    """
    if debug:
        print "httpresponse(%s)" %(data)
    header = "HTTP/1.1 200 OK\r\n"
    header += "Content-Type: application/json\r\n"
    header += "Access-Control-Allow-Origin: *\r\n"
    header += "Access-Control-Allow-Methods:\"GET,POST,OPTIONS,DELETE,PUT\""
    header += "\r\nContent-Length: %d\r\n\r\n" %len(data)
    response = header + data
    return response


class Job(object):

    def __init__(self, type, job, father, hshtypes, id):
        if debug:
            print "new Job(%s, %s, %s, %s, %s)" %(type, job, father, str(hshtypes), id)
        self.type = type
        self.job = job
        self.father = father
        self.hashtypes = hshtypes
        self.id = id

    def __eq__(self, other):
        sameType = self.type == other.type
        sameJob = self.job == other.job
        sameFather = self.father == other.father
        sameId = self.id == other.id
        return sameType and sameJob and sameId and sameFather

    def __ne__(self, other):
        diffType = self.type != other.type
        diffJob = self.job != other.job
        diffFather = self.father != other.father
        diffId = self.id != other.id
        return diffType or diffJob or diffId or diffFather

    def __str__(self):
        dic = {"type": self.type,
                "job": self.job,
                "father": self.father,
                "hashtypes": self.hashtypes,
                "id": self.id}
        return str(dic)

    def getJob(self):
        if debug:
            print "Job.getJob()"
        type, job, hshtypes, id = self.type, self.job, self.hashtypes, self.id
        father = self.father
        return [type, job, father, hshtypes, id]

    def getOneJob(self):
        if debug:
            print "Job.getOneJob()"
        try:
            type, job, hashtype = self.type, self.job, self.hashtypes.pop()
            id, empty = self.id, len(self.hashtypes)==0
            father = self.father
            return [type, job, father, hashtype, id], empty
        except IndexError:
            raise IndexError("no more hashtype to test")


class InfoJob(object):

    def __init__(self, nbdone=0, nbjobs=0, nbfound=0, nbpass=0, stime=None,
                    etime=None, how=None):
        self.nbdone = nbdone
        self.nbjobs = nbjobs
        self.nbfound = nbfound
        self.nbpass = nbpass
        self.stime = stime
        self.etime = etime
        self.how = how

    def getInfos(self):
        infos = dict()
        infos["nbdone"] = self.nbdone
        infos["nbjobs"] = self.nbjobs
        infos["nbfound"] = self.nbfound
        infos["nbpass"] = self.nbpass
        infos["stime"] = self.stime
        infos["etime"] = self.etime
        infos["how"] = self.how
        return infos


class APIProtocol(object, LineReceiver):
    # request is set to True when API is supposed to send HTTP requests, and is
    # set to False when it is supposed to send HTTP responses
    request = True
    # delimiter is used to separate HTTP requests received and sent by API
    delimiter = "\r\n\r\n"

    # ======================= PROTOCOL FUNCTIONS ======================= #
    def connectionMade(self):
        """
        Triggered when a connection is made.
        """
        self.buffer = ""
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "Connection made with %s:%d" %(host, port)
        # Log connection
        logger.log("Connection made with %s:%d" %(host, port))
        self.proto = {"NODETYPE": self.nodetype,
                        "LISTENING": self.listening,
                        "DO": self.do,
                        "FATHER": self.father,
                        "POLICY": self.policy,
                        "RESULT": self.result,
                        "PUT": self.put,
                        "GET": self.get,
                        "REMOVE": self.remove,
                        "STOP": self.stop,
                        "RESUME": self.resume,
                        "PURGE": self.purge,
                        "KICK": self.kick,
                        "OK": self.ok,
                        "ERROR": self.error}
        self.nodes = {"api": self.api,
                        "master": self.master,
                        "secondary": self.secondary,
                        "slave": self.slave,
                        "slavesync": self.slave}
        self.putActions = {"file": self.putFile,
                            "jobs": self.putJobs,
                            "hashes": self.putHashes,
                            "infos": self.putInfos,
                            "nbjobs": self.putNbJobs,
                            "policy": self.putPolicy}
        self.getActions = {"results": self.getResults,
                            "infos": self.getInfos,
                            "infosended": self.getInfosEnded,
                            "infonodes": self.getInfonodes,
                            "attacks": self.getAttacks,
                            "hashtypes": self.getHashtypes,
                            "policy": self.getPolicy,
                            "policies": self.getPolicies}
        self.removeActions = {"job": self.removeJob,
                                "policy": self.removePolicy}

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "Connection lost with %s:%d"%(host, port)
        # Log connection loss
        logger.log("Connection lost with %s:%d" %(host, port))
        # If masternode was disconnected
        if self == self.factory.master:
            self.factory.master = None
            # If there is a secondary node, then...
            if self.factory.secondary:
                jobs = self.factory.jobs
                fathers = self.factory.fathers
                # Send all informations, hashes and jobs to that secondary node
                for id in self.factory.infos.keys():
                    nbrem = self.factory.infos[id].nbdone
                    self.factory.secondary.sendPut("nbjobs", [nbrem, id])
                    if id in self.factory.hashes.keys():
                        hashes = self.factory.hashes[id]
                        secondary = self.factory.secondary
                        while hashes:
                            secondary.sendPut("hashes", [hashes[:150], id])
                            hashes = hashes[150:]
                    for job in jobs[id]:
                        chunk = getChunk[job.type](job.job)
                        newjob = [job.type, chunk, job.father, job.hashtypes, id]
                        self.factory.secondary.sendPut("jobs", [newjob, id])
                    self.factory.secondary.sendPut("fathers", [fathers[id], id])
                # Tell slavenodes to connect to that secondary
                host, port = secondarynode["host"], secondarynode["port"]
                for s in self.factory.slavenodes:
                    s.sendListening(host, port)
        if self == self.factory.secondary:
            self.factory.secondary = None
        if self in self.factory.slavenodes:
            self.factory.slavenodes.remove(self)
        if self == self.factory.api:
            self.factory.api = None

    def lineReceived(self, data):
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "APIProtocol.lineReceived(%s) from %s:%s" %(data, host, port)
        lines = data.split("\r\n")
        header = lines[0]
        # If it is not an HTTP/1.1 request, lose connection
        if "HTTP/1.1" not in header:
            self.transport.loseConnection()
            return
        # Else get all arguments
        r = re.compile("^([^:]+): (.*?)$", re.MULTILINE)
        request = dict((head, value) for (head, value) in r.findall("\n".join(x for x in lines[1:])))
        # If User-Agent is Octopus, then sender is part of Octopus
        # infrastructure, and API is supposed to send HTTP requests. Else,
        # sender is a browser, and API is supposed to send an HTTP response.
        self.request = True if request["User-Agent"] == "Octopus" else False
        addr = header.split()[1]
        p = urlparse.parse_qs(urlparse.urlparse(addr).query)
        if "cmd" in p.keys() and p['cmd']:
            self.requestReceived(p['cmd'][0])
        else:
            self.transport.loseConnection()

    def requestReceived(self, data):
        """
        Maps a command with its corresponding function
        """
        #if self.request:
            #data = zlib.decompress(data)
        if debug:
            print "APIProtocol.requestReceived(%s)" %(data)
        # Log received request
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        logger.log("Recv from %s:%d: %s"%(host, port, data))
        # Requests must be sent by JSON. Send back an error if it is not.
        if self.request:
            if data[-1] == "\x03":
                self.buffer += data[:-1]
                try:
                    cmd = json.loads(self.buffer)
                except ValueError as e:
                    self.sendError("Your request is not a JSON")
            else:
                self.buffer += data
                return
        else:
            try:
                cmd = json.loads(data)
            except ValueError as e:
                self.sendError("Your request is not a JSON")
#        self.buffer += data
#        try:
#            cmd = json.loads(self.buffer)
#        except ValueError as e:
#            #self.sendError("Your request is not a JSON")
#            return
        self.buffer = ""
        if cmd:
            # If cmd does not match any known function, then an error is sent.
            if cmd[0] in self.proto.keys():
                # If no masternode is connected, and no masternode wants to
                # connect, API sends an error.
                if not (self.factory.master or self.factory.secondary):
                    if not cmd[0] == "NODETYPE":
                        self.sendError("API is down")
                        return
                try:
                    self.proto[cmd[0]](*cmd[1:])
                except TypeError as e:
                    raise
                    self.sendError("Type error, probably wrong number of args")
                    return
            else:
                self.sendError("That function does not exist")

    def sendRequest(self, data):
        """
        sendRequest is used to send requests to other node, or to send
        responses to clients.
        """
        # Log sent request
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "APIProtocol.sendRequest(%s) to %s:%d" %(data, host, port)
        logger.log("Sent to %s:%d: %s"%(host, port, data))
        # Wrap data into an HTTP request or an HTTP response and send it
        if self.request:
            data += "\x03"
            while data:
                self.sendLine(self.wrap(data[:1000]))
                data = data[1000:]
        else:
            self.sendLine(self.wrap(data))
            # If an HTTP response was sent, then connection is cut
            self.transport.loseConnection()

    # ===================== END PROTOCOL FUNCTIONS ===================== #

    # ========================= RECV FUNCTIONS ========================= #
    def nodetype(self, type):
        """
        Answer to a NODETYPE command.
        """
        if debug:
            print "APIProtocol.nodetype(%s)" %(type)
        try:
            self.sendNodetype()
            self.nodes[type]()
        except KeyError as e:
            self.sendError("That nodetype does not exists")
            return

    def listening(self, host, port):
        """
        Answer to a LISTENING command. Should tell clients or slavenodes what
        is the address of the current Masternode.
        """
        pass

    def error(self, msg):
        pass

    def do(self, type, job, htypes, id):
        """
        Answer to a DO command. Used to send a job.
        """
        if debug:
            print "APIProtocol.do(%s, %s, %s, %s)" %(type, job, str(htypes), id)
        # Job name cannot contain any special character
        for char in charsets["s"] + " ":
            if char in id:
                self.sendError("Id cannot contain \"%s\"" %(char))
                # TODO: Remove hashes and infos
                return
        # Hashes must be sent to API before jobs
        if not id in self.factory.hashes.keys():
            self.sendError("No hash for your id, job cannot be done")
            # TODO: Remove hashes and infos
            return
        # API sends an error if the attack type does not exist
        if not type in jobParser.keys():
            self.sendError("That attack type does not exist")
            self.factory.hashes.pop(id)
            # TODO: Remove hashes and infos
            return
        # Check syntax of attack
        if not jobParser[type](job):
            if type[0] in ["a", "e", "i", "o"]:
                a = "an"
            else:
                a = "a"
            self.sendError("Your job is not %s %s job" %(a, type))
            self.factory.hashes.pop(id)
            # TODO: Remove hashes and infos
            return
        # If everything is OK, then do job
        self.sendOK("Your job is being processed")
        if not id in self.factory.jobs:
            self.factory.jobs[id] = deque()
        master = self.factory.master or self.factory.secondary
        if not self.factory.infos[id].stime:
            self.factory.infos[id].stime = time.time()
        master.sendDo(type, job, htypes, id)
        if not id in self.factory.results:
            self.factory.results[id] = set()

    def policy(self, policy, hashtypes, id):
        """
        Same function as do (but job is replaced by a policy)
        """
        if debug:
            print "APIProtocol.policy(%s, %s, %s)" %(policy, str(hashtypes), id)
        for char in charsets["s"] + " ":
            if char in id:
                self.sendError("Id cannot contain \"%s\"" %(char))
                return
        if not id in self.factory.hashes.keys():
            self.sendError("No hash for your id, job cannot be done")
            return
        if not policy in policies:
            self.sendError("That policy does not exist")
            self.factory.hashes.pop(id)
            return
        jinfos = [hashtypes, id]
        # If everything is OK, read policy and perform DO actions
        checkFile("%s/policies/%s.policy" %(home, policy))
        with open("%s/policies/%s.policy" %(home, policy), "r") as f:
            for line in f:
                job = json.loads(line.strip("\n")) + jinfos
                self.requestReceived(json.dumps(job))

    def result(self, results, id):
        """
        Answer to a RESULT command. Used to send the result of a request.
        """
        # No answer if id does not exist
        if not id in self.factory.results.keys():
            return
        # All hashes corresponding to results are removed
        self.removeHashes(results, id)
        # Update results list and nbfound
        for result in results:
            try:
                if not result in self.factory.results[id]:
                    try:
                        self.factory.infos[id].nbfound += 1
                    except KeyError:
                        self.factory.infosEnded[id].nbfound += 1
                    self.factory.results[id].add(result)
                    with open("%s/results/%s" %(home, id), "a") as f:
                        f.write(result + "\n")
            except KeyError:
                pass
        try:
            done = self.factory.infos[id].nbdone
            tot = self.factory.infos[id].nbjobs
            found = self.factory.infos[id].nbfound
            nbpass = self.factory.infos[id].nbpass
            if (done == tot) or (found == nbpass):
                self.factory.infos[id].etime = time.time()
                self.factory.infosEnded[id] = self.factory.infos.pop(id)
                self.factory.infosEnded[id].how = "finished"
        except KeyError as e:
            pass

    def father(self, father, nb, id):
        if not id in self.factory.times:
            self.factory.times[id] = {"times": dict(), "found": 0}
        self.factory.times[id]["times"][father] = time.time()
        if not id in self.factory.fathers:
            self.factory.fathers[id] = dict()
        self.factory.fathers[id][father] = nb

    def put(self, type, objects):
        """
        Answer to a PUT command. Used to upload files such as dictionaries and
        hashfiles.
        """
        if debug:
            print "APIProtocol.put(%s, ...)" %(type)
        try:
            self.putActions[type](*objects)
        except KeyError as e:
            self.sendError("Cannot put that kind of objects")

    def get(self, type, objects):
        """
        Answer to a GET command. Used to get information about slavenodes and
        job requests (results, state).
        """
        if debug:
            print "APIProtocol.get(%s, ...)" %(type)
        try:
            self.getActions[type](*objects)
        except KeyError as e:
            self.sendError("Cannot get that kind of objects")

    def remove(self, type, objects):
        """
        Answer to a GET command. Used to get information about slavenodes and
        job requests (results, state).
        """
        if debug:
            print "APIProtocol.remove(%s, ...)" %(type)
        try:
            self.removeActions[type](*objects)
        except KeyError as e:
            self.sendError("Cannot get that kind of objects")

    def removeJob(self, job):
        if debug:
            print "APIProtocol.removeJob(%s)" %(str(job))
        father = job[2]
        id = job[4]
        if id in self.factory.jobs.keys():
            mhome = masternode["vars"]["HOME"]
            shome = secondarynode["vars"]["HOME"]
            #chunk = job[1].replace(mhome, home).replace(shome, home)
            chunk = replace_multiple(job[1], {mhome: home, shome: home})
            job = Job(job[0], chunk, job[2], job[3], job[4])
            if job in self.factory.jobs[id]:
                while job in self.factory.jobs[id]:
                    self.factory.jobs[id].remove(job)
                if id in self.factory.infos.keys():
                    self.factory.infos[id].nbdone += 1
                    nbdone = self.factory.infos[id].nbdone
            self.factory.fathers[id][father] -= 1
            if self.factory.fathers[id][father] == 0:
                m = matrices.Matrix(home, father.split(":", 1))
                i = self.factory.times[id]["found"]
                found = self.factory.infos[id].nbfound
                nbpass = self.factory.infos[id].nbpass
                j = (found*100)/nbpass
                self.factory.times[id]["found"] = j
                m.update(i, j)
                m.save()
                self.factory.fathers[id].pop(father)
            if not self.factory.jobs[id]:
                self.factory.jobs.pop(id)
                self.factory.fathers.pop(id)
            try:
                done = self.factory.infos[id].nbdone
                tot = self.factory.infos[id].nbjobs
                found = self.factory.infos[id].nbfound
                nbpass = self.factory.infos[id].nbpass
                if (done == tot) or (found == nbpass):
                    self.factory.infos[id].etime = time.time()
                    etime = self.factory.infos[id].etime
                    self.factory.infosEnded[id] = self.factory.infos.pop(id)
                    self.factory.infosEnded[id].how = "finished"
                    how = self.factory.infosEnded[id].how
            except KeyError as e:
                pass

    def removePolicy(self, policy):
        if debug:
            print "APIProtocol.removePolicy(%s)" %(policy)
        os.remove("%s/policies/%s.policy" %(home, policy))
        policies.remove(policy)
        with open("%s/policies/list" %(home), "w") as f:
            pols = "\n".join(policies)
            f.write(pols)
        self.sendOK("Policy %s removed" %(policy))

    def stop(self, id):
        if debug:
            print "APIProtocol.stop(%s)" %(id)
        nbjobs = self.factory.infos[id].nbjobs
        if self.factory.master:
            self.factory.master.sendStop(id)
        if self.factory.secondary:
            self.factory.secondary.sendStop(id)
        try:
            self.factory.infos[id].etime = time.time()
            etime = self.factory.infos[id].etime
            self.factory.infosEnded[id] = self.factory.infos.pop(id)
            self.factory.infosEnded[id].how = "stopped"
            backup.save()
        except KeyError as e:
            self.sendError("Key error")

    def resume(self, id):
        if debug:
            print "APIProtocol.resume(%s)" %(id)
        master = self.factory.master or self.factory.secondary
        if not id in self.factory.infosEnded.keys():
            return
        if not self.factory.infosEnded[id].how == "stopped":
            return
        if master:
            hashes, jobs, results, infos = backup.resume(id)
            with open("/app/octopus/zpoerhez", "a") as f:
                f.write(str(hashes) + "\n")
                f.write(str(jobs) + "\n")
                f.write(str(infos))
            if hashes and jobs and id in self.factory.infosEnded.keys():
                self.factory.jobs[id] = deque([Job(*job) for job in jobs])
                self.factory.hashes[id] = hashes
                self.factory.results[id] = results
                self.factory.infos[id] = InfoJob(**infos)
                self.factory.infosEnded.pop(id)
                jobs = self.factory.jobs
                fathers = self.factory.fathers
                nbrem = self.factory.infos[id].nbdone
                master.sendPut("nbjobs", [nbrem, id])
                if id in self.factory.hashes.keys():
                    hashes = self.factory.hashes[id]
                    while hashes:
                        master.sendPut("hashes", [hashes[:150], id])
                        hashes = hashes[150:]
                for job in jobs[id]:
                    job = job.getJob()
                    chunk = getChunk[job[0]](job[1])
                    newjob = [job[0], chunk, job[2], job[3], job[4]]
                    master.sendPut("jobs", [newjob, id])
                master.sendPut("fathers", [fathers[id], id])

    def purge(self, id):
        if debug:
            print "APIProtocol.purge(%d)" %(id)
        self.popAll(id)
        if self.factory.master:
            self.factory.master.sendPurge(id)
        if self.factory.secondary:
            self.factory.secondary.sendPurge(id)

    def api(self):
        """
        Answer to a NODETYPE manager command. Sent by Manager when a connection
        is made.
        """
        if debug:
            print "APIProtocol.api()"
        self.factory.api = self

    def master(self):
        """
        Answer to a NODETYPE master command. Sent by Masternode when a
        connection is made.
        """
        if debug:
            print "APIProtocol.master()"
        self.factory.master = self
        jobs = self.factory.jobs
        fathers = self.factory.fathers
        nbjobs = self.factory.nbjobs
        for id in self.factory.infos.keys():
            nbrem = self.factory.infos[id].nbdone
            self.factory.master.sendPut("nbjobs", [nbrem, id])
            if id in self.factory.hashes.keys():
                hashes = self.factory.hashes[id]
                while hashes:
                    self.factory.master.sendPut("hashes", [hashes[:150], id])
                    hashes = hashes[150:]
            for job in jobs[id]:
                job = job.getJob()
                chunk = getChunk[job[0]](job[1])
                newjob = (job[0], chunk, job[2], job[3], job[4])
                self.factory.master.sendPut("jobs", [newjob, id])
            self.factory.master.sendPut("fathers", [fathers[id], id])
        host = masternode["host"]
        port = masternode["port"]
        for s in self.factory.slavenodes:
            s.sendListening(host, port)

    def secondary(self):
        """
        Answer to a NODETYPE secondary command. Sent by Secondarynode when a
        connection is made.
        """
        if debug:
            print "APIProtocol.secondary()"
        self.factory.secondary = self
        if not self.factory.master:
            for id in self.factory.infos.keys():
                hashes = self.factory.hashes[id]
                secondary = self.factory.secondary
                while hashes:
                    secondary.sendPut("hashes", [hashes[:150], id])
                    hashes = hashes[150:]
                jobs = self.factory.jobs
                fathers = self.factory.fathers
                nbjobs = self.factory.nbjobs
            for id in self.factory.infos.keys():
                nbrem = self.factory.infos[id].nbdone
                self.factory.secondary.sendPut("nbjobs", [nbrem, id])
                for job in jobs[id]:
                    job.getJob()
                    chunk = getChunk[job[0]](job[1])
                    newjob = (job[0], chunk, job[2], job[3], job[4])
                    self.factory.secondary.sendPut("jobs", [newjob, id])
                self.factory.secondary.sendPut("fathers", [fathers[id], id])
            host = secondarynode["host"]
            port = secondarynode["port"]
            for s in self.factory.slavenodes:
                s.sendListening(host, port)

    def slave(self):
        """
        Answer to a NODETYPE slave command. Sent by a slavenode when a
        connection is made.
        """
        if debug:
            print "APIProtocol.slave()"
        self.factory.slavenodes.append(self)
        if self.factory.master:
            host = masternode["host"]
            port = masternode["port"]
            self.sendListening(host, port)
        elif self.factory.secondary:
            host = secondarynode["host"]
            port = secondarynode["port"]
            self.sendListening(host, port)

    def putNbJobs(self, nb, id):
        if debug:
            print "APIProtocol.putNbJobs(%d, %s)" %(nb, id)
        if not "nbjobs" in self.factory.infos[id].getInfos().keys():
            self.factory.infos[id].nbjobs = nb
            self.factory.nbjobs[id] = nb
        else:
            self.factory.infos[id].nbjobs += nb
            self.factory.nbjobs[id] += nb

    def putFile(self, chunk, path):
        """
        Answer to a PUT dictionary command. Used to store a dictionary.
        """
        pass

    def putHashes(self, hashes, id):
        """
        Answer to a PUT hashes command. Used to store a hashfile.
        """
        if debug:
            print "APIProtocol.putHashes(%s, %s)" %(str(hashes[:3]), id)
        for char in charsets["s"] + " ":
            if char in id:
                self.sendError("Id cannot contain \"%s\"" %char)
                return
        if not id.strip():
            self.sendError("You must give an id to your attack")
            return
        if id in self.factory.hashes.keys() and id in self.factory.jobs.keys():
            self.sendError("That id already exists")
            return
        else:
            master = self.factory.master or self.factory.secondary
            nbhashes = len(hashes)
            toSend = list(hashes)
            if master:
                while toSend:
                    master.sendPut("hashes", [toSend[:150], id])
                    toSend = toSend[150:]
            if not os.path.isdir("%s/%s" %(tmpdir, id)):
                os.mkdir("%s/%s" %(tmpdir, id))
            if not id in self.factory.infos.keys():
                self.factory.infos[id] = InfoJob()
                self.factory.nbjobs[id] = 0
            self.factory.infos[id].nbpass += nbhashes
            if id in self.factory.hashes.keys():
                self.factory.hashes[id] += hashes
            else:
                self.factory.hashes[id] = hashes
            self.sendOK("Hashes uploaded")

    def putJobs(self, job, id):
        if debug:
            print "APIProtocol.putJobs(%s, %s)" %(str(job), id)
        if not id in self.factory.jobs.keys():
            self.factory.jobs[id] = deque()
        nbjobs = self.factory.infos[id].nbjobs
        path = "%s/tmp/%s/part%d" %(home, id, nbjobs)
        chunk = saveChunk[job[0]](job[1], path)
        newjob = Job(job[0], chunk, job[2], job[3], job[4])
        self.factory.jobs[id].append(newjob)
        self.factory.infos[id].nbjobs += 1

    def putInfos(self, infos):
        if debug:
            print "APIProtocol.putInfos(%s)" %(str(infos))
        host = self.transport.getPeer().host
        port = self.transport.getPeer().port
        addr = "%s:%d" %(host, port)
        self.factory.infoslaves[addr] = infos

    def putPolicy(self, name, jobs):
        if debug:
            print "APIProtocol.putPolicy(%s, %s)" %(name, str(jobs))
        if not name:
            self.sendError("You must give a name to your policy")
            return
        if name in policies:
            self.sendError("Policy already exists")
            return
        cset = charsets["l"] + charsets["u"]
        cset += charsets["d"] + "_-"
        for char in name:
            if char not in cset:
                self.sendError("Policy name cannot contain %s" %char)
                return
        if not jobs:
            self.sendError("You must give at least one attack")
            return
        for job in jobs:
            type = job[0]
            attack = job[1]
            if not type in jobParser.keys():
                self.sendError("One of the attack types does not exist")
                return
            if not jobParser[type](attack):
                self.sendError("Type error")
                return
        with open("%s/policies/list" %home, "a") as f:
            f.write(name + "\n")
        with open("%s/policies/%s.policy" %(home, name), "w") as f:
            p = "\n".join(json.dumps(["DO", job[0], job[1]]) for job in jobs)
            f.write(p)
        self.sendOK("Policy added successfully")
        policies.append(name)

    def getResults(self, id):
        """
        Answer to a GET results command. Returns the list of results
        corresponding to a given client.
        """
        if debug:
            print "APIProtocol.getResults(%s)" %(id)
        if id in self.factory.results.keys():
            self.sendResult(list(self.factory.results[id]))
        else:
            try:
                with open("%s/results/%s" %(home, id)) as f:
                    results = [r.strip("\n") for r in f.xreadlines()]
                self.sendResult(results)
            except IOError as e:
                if e.errno == errno.ENOENT:
                    self.sendError("No result for your id")
                else:
                    raise

    def getInfonodes(self):
        if debug:
            print "APIProtocol.getInfonodes()"
        self.factory.infoslaves = dict()
        nan = {"program": "unknown", "cpu": 0}
        for s in self.factory.slavenodes:
            host = s.transport.getPeer().host
            port = s.transport.getPeer().port
            addr = "%s:%d" %(host, port)
            self.factory.infoslaves[addr] = nan
            s.sendGet("infos", [])
        reactor.callLater(0.3, self.sendInfonodes)

    def getInfos(self):
        if debug:
            print "APIProtocol.getInfos()"
        self.sendInfos()

    def getInfosEnded(self):
        if debug:
            print "APIProtocol.getInfosEnded()"
        self.sendInfosEnded()

    def getAttacks(self):
        if debug:
            print "APIProtocol.getAttacks()"
        self.sendAttacks()

    def getHashtypes(self):
        if debug:
            print "APIProtocol.getHashtypes()"
        self.sendHashtypes()

    def getPolicies(self):
        if debug:
            print "APIProtocol.getPolicies()"
        self.sendResult(policies)

    def getPolicy(self, name):
        if debug:
            print "APIProtocol.getPolicy(%s)" %(name)
        checkFile("%s/policies/%s.policy" %(home, name))
        policy = open("%s/policies/%s.policy" %(home, name), "r").read()
        policy = [json.loads(a) for a in policy.splitlines() if len(a) > 0]
        self.sendResult(policy)

    def kick(self, addr):
        if debug:
            print "APIProtocol.kick(%s)" %(addr)
        host, port = addr.split(":")
        p = lambda s: s.transport.getPeer()
        f = lambda p: (p.host == host and p.port == int(port))
        [s.sendKick() for s in self.factory.slavenodes if f(p(s))]

    def ok(self, msg):
        pass

    # ======================= END RECV FUNCTIONS ======================= #

    # ========================= SEND FUNCTIONS ========================= #
    def sendNodetype(self):
        if debug:
            print "APIProtocol.sendNodetype"
        self.sendRequest(json.dumps(["NODETYPE", "api"]))

    def sendOK(self, msg):
        if debug:
            print "APIProtocol.sendOK"
        self.sendRequest(json.dumps(["OK", msg]))

    def sendError(self, msg):
        if debug:
            print "APIProtocol.sendError"
        self.sendRequest(json.dumps(["ERROR", msg]))

    def sendListening(self, host, port):
        if debug:
            print "APIProtocol.sendListening"
        self.sendRequest(json.dumps(["LISTENING", host, port]))

    def sendDo(self, type, job, htypes, id):
        if debug:
            print "APIProtocol.sendDo"
        self.sendRequest(json.dumps(["DO", type, job, htypes, id]))

    def sendGet(self, type, object):
        if debug:
            print "APIProtocol.sendGet"
        self.sendRequest(json.dumps(["GET", type, object]))

    def sendPut(self, type, object):
        if debug:
            print "APIProtocol.sendPut"
        self.sendRequest(json.dumps(["PUT", type, object]))

    def sendStop(self, id):
        if debug:
            print "APIProtocol.sendStop"
        self.sendRequest(json.dumps(["STOP", id]))

    def sendPurge(self, id):
        if debug:
            print "APIProtocol.sendPurge"
        self.sendRequest(json.dumps(["PURGE", id]))

    def sendKick(self):
        if debug:
            print "APIProtocol.sendKick"
        self.sendRequest(json.dumps(["KICK"]))

    def sendAttacks(self):
        if debug:
            print "APIProtocol.sendAttacks"
        self.sendResult(commands.keys())

    def sendHashtypes(self):
        if debug:
            print "APIProtocol.sendHashtypes"
        self.sendResult(hashtypes)

    def sendInfos(self):
        if debug:
            print "APIProtocol.sendInfos"
        infos = self.factory.infos
        infos = dict((id, infos[id].getInfos()) for id in infos)
        self.sendResult(infos)

    def sendInfosEnded(self):
        if debug:
            print "APIProtocol.sendInfosEnded"
        infos = self.factory.infosEnded
        infos = dict((id, infos[id].getInfos()) for id in infos)
        self.sendResult(infos)

    def sendInfonodes(self):
        if debug:
            print "APIProtocol.sendInfonodes"
        self.sendResult(self.factory.infoslaves)

    def sendResult(self, result):
        if debug:
            print "APIProtocol.sendResult"
        self.sendRequest(json.dumps(["RESULT", result]))

    # ======================= END RECV FUNCTIONS ======================= #

    # ========================= MISC FUNCTIONS ========================= #
    def removeHashes(self, results, id):
        if debug:
            print "APIProtocol.removeHashes(%s, %s)" %(str(results[:3]), id)
        hashes = self.factory.hashes[id]
        for result in results:
            for hash in hashes:
                if result.split(":")[1] in hash:
                    hashes.remove(hash)

    def wrap(self, data):
        if debug:
            print "APIProtocol.wrap(%s)" %(data)
        if self.request:
            return httprequest(data)
        else:
            return httpresponse(data)

    def popAll(self, id):
        if debug:
            print "APIProtocol.popAll(%s)" %(id)
        if id in self.factory.results.keys():
            self.factory.results.pop(id)
        if id in self.factory.jobs.keys():
            self.factory.jobs.pop(id)
        if id in self.factory.nbjobs.keys():
            self.factory.nbjobs.pop(id)
        if id in self.factory.infos.keys():
            self.factory.infos.pop(id)
        if id in self.factory.infosEnded.keys():
            self.factory.infosEnded.pop(id)
        if os.path.isdir("%s/tmp/%s" %(home, id)):
            shutil.rmtree("%s/tmp/%s" %(home, id))
        if os.path.isfile("%s/results/%s" %(home, id)):
            os.remove("%s/results/%s" %(home, id))

    # ======================= END MISC FUNCTIONS ======================= #

class APIFactory(object, protocol.ClientFactory, protocol.ServerFactory):

    def __init__(self, protocol=APIProtocol):
        self.protocol = protocol
        self.infos = dict()
        self.infosEnded = dict()
        self.results = dict()
        self.jobs = dict()
        self.fathers = dict()
        self.nbjobs = dict()
        self.times = dict()
        self.hashes = dict()
        self.slavenodes = []
        self.api = None
        self.master = None
        self.secondary = None

    def resume(self):
        pass

factory = APIFactory()
backup = backupdb.BackupDB(factory, reactor, backupath)
backup.init()
reactor.listenTCP(PORT, factory, interface=HOST)
reactor.run()
backup.cur.close()
backup.con.close()
logger.write()
if os.path.isdir("%s/tmp"%home):
    shutil.rmtree("%s/tmp"%home)
os.mkdir("%s/tmp"%home)
