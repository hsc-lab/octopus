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
from twisted.internet import protocol, reactor, defer
from collections import deque
from chunkify import chunkify, getChunk, saveChunk
from params import api, masternode, secondarynode, dictpath
from md5sum import md5sum
import shutil
import os
import json
import re
import urlparse
import urllib2
import optparse
import random
import logs
#import zlib

api_host = api["host"]
api_port = api["port"]

OCTOPUS = """
  ___       _
 / _ \\  ___| |_ ___  _ __  _   _ ___
| | | |/ __| __/ _ \\| '_ \\| | | / __|
| |_| | (__| || (_) | |_) | |_| \\__ \\
 \\___/ \\___|\\__\\___/| .__/ \\__,_|___/
                    |_|
"""
print OCTOPUS
print "Masternode started"


def httprequest(data):
    #data = zlib.compress(data)
    request = "GET /?cmd=%s HTTP/1.1\r\n" %urllib2.quote(data)
    request += "User-Agent: Octopus"
    return request


def parse_args():
    """
    Arguments parser
    """
    usage = """usage: %prog [options]"""

    parser = optparse.OptionParser(usage)

    help = "Use as secondary masternode"
    parser.add_option("-s", "--secondary", action = "store_true", help = help)

    help = "Debug mode"
    parser.add_option("-d", "--debug", action = "store_true", help = help)

    options, args = parser.parse_args()
    return options

debug = parse_args().debug
is_master = not parse_args().secondary
type = (is_master and "master") or ((not is_master) and "secondary")
if is_master:
    config = masternode
else:
    config = secondarynode

home = config["vars"]["HOME"]
HOST = config["host"]
PORT = config["port"]

logger = logs.Logger("%s/master.log" %(home), reactor)


class Job(object):

    def __init__(self, type, job, father, hashtypes, id):
        self.type = type
        self.job = job
        self.father = father
        self.hashtypes = hashtypes
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

    def getJob(self):
        type, job, hashtypes, id = self.type, self.job, self.hashtypes, self.id
        father = self.father
        return [type, job, father, hashtypes, id]

    def getOneJob(self):
        try:
            type, job, hashtype = self.type, self.job, self.hashtypes.pop()
            id, empty = self.id, len(self.hashtypes)==0
            return [type, job, hashtype, id], empty
        except IndexError:
            raise IndexError("no more hashtype to test")


class MasterProtocol(object, LineReceiver):
    delimiter = "\r\n\r\n"
    id = None
    hashtype = None

    # ======================= PROTOCOL FUNCTIONS ======================= #
    def connectionMade(self):
        self.buffer = ""
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        logger.log("Connection made with %s:%d"%(host, port))
        if debug:
            print "Connection made with %s:%d" %(host, port)
        self.proto = {"NODETYPE": self.nodetype,
                        "DO": self.do,
                        "RESULT": self.result,
                        "RESULTP": self.resultp,
                        "PUT": self.put,
                        "GET": self.get,
                        "STOP": self.stop,
                        "PURGE": self.purge,
                        "ERROR": (lambda msg: None),
                        "WAIT": self.wait}
        self.nodes = {"api": self.api,
                        "master": self.master,
                        "secondary": self.secondary,
                        "slave": self.slave,
                        "slavesync": self.slavesync}
        self.putActions = {"fathers": self.putFathers,
                            "jobs": self.putJobs,
                            "nbjobs": self.putNbJobs,
                            "hashes": self.putHashes}
        self.getActions = {"results": self.getResults,
                            "chunk": self.getChunk,
                            "dictionaries": self.getDictionaries,
                            "dictlist": self.getDictlist}
        self.sendNodetype()

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "Connection lost with %s:%d"%(host, port)
        logger.log("Connection lost with %s:%d"%(host, port))
        if self == self.factory.master:
            self.factory.master = None
        elif self == self.factory.secondary:
            self.factory.secondary = None
        elif self in self.factory.slavenodes:
            self.factory.slavenodes.remove(self)
            peer = self.transport.getPeer()
            ipport = "%s:%d" %(peer.host, peer.port)
            if ipport in self.factory.deferreds:
                self.factory.deferreds.pop(ipport)
            if self.job:
                if not self.id in self.factory.jobs.keys():
                    self.factory.jobs[self.id] = deque()
                if self.hashtype:
                    self.job.hashtypes.append(self.hashtype)
                if not self.job in self.factory.jobs[self.id]:
                    self.factory.jobs[self.id].append(self.job)
        elif self == self.factory.api:
            self.factory.api = None

    def lineReceived(self, data):
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "MasterProtocol.lineReceived(%s) from %s:%s" %(data, host, port)
        lines = data.split("\r\n")
        request = dict()
        header = lines[0]
        if "HTTP/1.1" not in header:
            self.transport.loseConnection()
            return
        r = re.compile("^([^:]+): (.*?)$", re.MULTILINE)
        request = dict((head, value) for (head, value) in r.findall(data[1:]))
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
        #data = zlib.decompress(data)
        if debug:
            print "MasterProtocol.requestReceived(%s)" %(data)
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        logger.log("Recv from %s:%d: %s" %(host, port, data))
        if data[-1] == "\x03":
            self.buffer += data[:-1]
            try:
                cmd = json.loads(self.buffer)
            except ValueError as e:
                self.sendError("Your request is not a JSON")
        else:
            self.buffer += data
            return
#        self.buffer += data
#        try:
#            cmd = json.loads(self.buffer)
#        except ValueError as e:
#            return
        self.buffer = ""
        if cmd:
            if cmd[0] in self.proto.keys():
                try:
                    self.proto[cmd[0]](*cmd[1:])
                except TypeError as e:
                    raise
                    #self.sendError(str(e))
                    #return
            else:
                self.sendError("Function %s() does not exist" %cmd[0].lower())

    def sendRequest(self, data):
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "MasterProtocol.sendRequest(%s) to %s:%d" %(data, host, port)
        logger.log("Sent to %s:%d: %s"%(host, port, data))
        data += "\x03"
        while data:
            self.sendLine(httprequest(data[:1000]))
            data = data[1000:]


    # ===================== END PROTOCOL FUNCTIONS ===================== #

    # ========================= RECV FUNCTIONS ========================= #
    def nodetype(self, type):
        """
        Answer to a NODETYPE command.
        """
        if debug:
            print "MasterProtocol.nodetype(%s)" %(type)
        try:
            self.nodes[type]()
        except KeyError as e:
            self.sendError("Nodetype %s does not exists"%str(e))
            return

    def do(self, type, job, hashtypes, id):
        """
        Answer to a DO command. Used to send a job.
        """
        if debug:
            print "MasterProtocol.do(id=%s)" %(id)
        chunks = chunkify(type, job, id)
        if not id in self.factory.fathers:
            self.factory.fathers[id] = dict()
        nb = len(chunks)
        father = "%s:%s" %(type, job)
        self.factory.fathers[id][father] = nb
        self.factory.api.sendFather(father, nb, id)
        for chunk in chunks:
            self.addTask(type, chunk, father, hashtypes, id)

    def result(self, results):
        """
        Answer to a RESULT command. Used to send the result of a request.
        """
        if debug:
            print "MasterProtocol.result(%s)" %(str(results[:3]))
        if self.id:
            if self.id in self.factory.protocols:
                self.factory.protocols[self.id].remove(self)
            self.factory.api.sendResult(results, self.id)
            if self.id in self.factory.jobs.keys():
                if not self.job in self.factory.jobs[self.id]:
                    self.factory.api.sendRemove(self.job.getJob())
                self.job = None
                self.father = None
                self.hashtype = None
                self.removeHashes(results)
            else:
                self.factory.api.sendRemove(self.job.getJob())
                try:
                    shutil.rmtree("%s/tmp/%s" %(home, self.id))
                except OSError as e:
                    print e.message
        self.work()

    def resultp(self, results):
        """
        Answer to a RESULTP command. Used to send the result of a request.
        """
        if debug:
            print "MasterProtocol.resultp(%s)" %(str(results[:3]))
        id = self.id
        if id:
            self.factory.api.sendResult(results, id)
            self.removeHashes(results)
            if not self.id in self.factory.jobs.keys():
                try:
                    shutil.rmtree("%s/tmp/%s" %(home, self.id))
                except OSError as e:
                    print e.message

    def put(self, type, objects):
        """
        Answer to a PUT command. Used to upload files such as dictionaries and
        hashfiles.
        """
        if debug:
            print "MasterProtocol.put(%s, ...)" %(type)
        try:
            self.putActions[type](*objects)
        except KeyError as e:
            self.sendError("Cannot put %s objects" %str(e))

    def get(self, type, objects):
        """
        Answer to a GET command. Used to get information about slavenodes and
        job requests (results, state).
        """
        if debug:
            print "MasterProtocol.get(%s, ...)" %(type)
        try:
            self.getActions[type](*objects)
        except KeyError as e:
            self.sendError("Cannot get %s objects" %str(e))

    def stop(self, id):
        if debug:
            print "MasterProtocol.stop(%s)" %(id)
        try:
            self.factory.jobs.pop(id)
            shutil.rmtree("%s/tmp/%s" %(home, id))
            protocols = self.factory.protocols.pop(id)
            for slave in protocols:
                slave.id = None
                slave.sendStop()
        except KeyError as e:
            self.sendError(str(e))

    def purge(self, id):
        if debug:
            print "MasterProtocol.purge(%s)" %(id)
        try:
            self.factory.jobs.pop(id)
            self.factory.fathers.pop(id)
        except KeyError as e:
            self.sendError(str(e))
        if os.path.isdir("%s/tmp/%s" %(home, id)):
            shutil.rmtree("%s/tmp/%s" %(home, id))

    def api(self):
        """
        Answer to a NODETYPE api command. Sent by API when a connection
        is made.
        """
        if debug:
            print "MasterProtocol.api()"
        self.factory.api = self

    def master(self):
        """
        Answer to a NODETYPE master command. Sent by Masternode when a
        connection is made.
        """
        if debug:
            print "MasterProtocol.master()"
        self.factory.master = self

    def secondary(self):
        """
        Answer to a NODETYPE secondary command. Sent by Secondarynode when a
        connection is made.
        """
        if debug:
            print "MasterProtocol.secondary()"
        self.factory.secondary = self

    def slave(self):
        """
        Answer to a NODETYPE slave command. Sent by a slavenode when a
        connection is made.
        """
        if debug:
            print "MasterProtocol.slave()"
        self.factory.slavenodes.append(self)
        self.job = None
        self.father = None
        self.id = None
        self.work()

    def slavesync(self):
        """
        Answer to a NODETYPE slave command. Sent by a slavenode when a
        connection is made and when dictionaries synchronization is wanted.
        """
        if debug:
            print "MasterProtocol.slave()"
        self.job = None
        self.father = None
        self.id = None

    def putFathers(self, fathers, id):
        """
        Answer to a PUT father command.
        """
        self.factory.fathers[id] = fathers

    def putJobs(self, job, id):
        if debug:
            print "MasterProtocol.putJobs(id=%s)" %(id)
        if not id in self.factory.jobs.keys():
            self.factory.jobs[id] = deque()
        if not os.path.isdir("%s/tmp/%s" %(home, id)):
            os.mkdir("%s/tmp/%s" %(home, id))
        count = self.factory.nbjobs[id]
        self.factory.nbjobs[id] += 1
        path = "%s/tmp/%s/part%d" %(home, id, count)
        if os.path.isfile(path):
            os.remove(path)
        chunk = saveChunk[job[0]](job[1], path)
        father = job[2]
        newjob = Job(job[0], chunk, father, job[3], job[4])
        self.factory.jobs[id].append(newjob)
        self.fire()

    def putNbJobs(self, nbjobs, id):
        self.factory.nbjobs[id] = nbjobs

    def putHashes(self, hashes, id):
        """
        Answer to a PUT hashes command. Used to store a hashfile.
        """
        if debug:
            print "MasterProtocol.putHashes(id=%s)" %(id)
        if not os.path.isdir("%s/tmp/%s" %(home, id)):
            os.mkdir("%s/tmp/%s" %(home, id))
        with open("%s/tmp/%s/hashes"%(home, id), "a") as f:
            dico = "\n".join(hash for hash in hashes)
            try:
                f.write(dico + "\n")
            except UnicodeEncodeError:
                pass
        self.sendOK("Hashes uploaded")

    def getDictionaries(self, dictlist):
        for dname in dictlist:
            print "Sending %s..." %(dname)
            with open("%s/%s.txt" %(dictpath, dname), "r") as g:
                dict = g.read().decode('latin-1').encode('utf-8')
                dict = dict.split("\n")
                while dict:
                    self.sendPut("dictionary", [dict[:100000], dname])
                    dict = dict[100000:]
            print "%s sent!" %(dname)
        self.factory.slavenodes.append(self)
        self.work()

    def getChunk(self, dic, nb, step):
        with open("%s/%s.txt" %(dictpath, dic), "r") as f:
            chunk = "\n".join(f.readlines()[nb*step:(nb+1)*step])
            self.sendPut("dictionary", [chunk, dic])

    def getDictlist(self):
        dictlist = dict()
        with open("%s/dictionaries" %(dictpath), "r") as f:
            for line in f:
                line = line.replace("\n", "")
                md5digest = md5sum("%s/%s.txt" %(dictpath, line))
                dictlist[md5digest] = line
        self.sendPut("dictlist", [dictlist])

    def getResults(self, id):
        """
        Answer to a GET results command. Returns the list of results
        corresponding to a given client.
        """
        pass

    def wait(self):
        if debug:
            print "MasterProtocol.wait()"
        if not self.id in self.factory.jobs.keys():
            self.factory.jobs[self.id] = deque()
        self.job.hashtypes.append(self.hashtype)
        if self.job in self.factory.jobs[self.id]:
            self.factory.jobs[self.id].remove(self.job)
        self.factory.jobs[self.id].appendleft(self.job)
        self.id = None
        self.job = None

    # ======================= END RECV FUNCTIONS ======================= #

    # ========================= SEND FUNCTIONS ========================= #
    def sendNodetype(self):
        self.sendRequest(json.dumps(["NODETYPE", self.factory.type]))

    def sendOK(self, msg):
        self.sendRequest(json.dumps(["OK", msg]))

    def sendError(self, msg):
        self.sendRequest(json.dumps(["ERROR", msg]))

    def sendDo(self, type, job, hashtype, id):
        self.id = id
        self.sendRequest(json.dumps(["DO", type, job, hashtype]))

    def sendFather(self, father, nb, id):
        self.sendRequest(json.dumps(["FATHER", father, nb, id]))

    def sendGet(self, type, object):
        pass

    def sendPut(self, type, object):
        # TODO: UTF-8 conv
        try:
            self.sendRequest(json.dumps(["PUT", type, object]))
        except UnicodeDecodeError as e:
            print e.message

    def sendRemove(self, job):
        self.sendRequest(json.dumps(["REMOVE", "job", [job]]))

    def sendResult(self, result, id=0):
        self.sendRequest(json.dumps(["RESULT", result, id]))

    def sendStop(self):
        self.sendRequest(json.dumps(["STOP"]))

    # ======================= END RECV FUNCTIONS ======================= #

    # ========================= MISC FUNCTIONS ========================= #
    def removeHashes(self, results):
        if debug:
            print "MasterProtocol.removeHashes(%s)" %(str(results[:3]))
        try:
            with open("%s/tmp/%s/hashes" %(home, self.id), "r") as f:
                hashes = [h.strip("\n") for h in f.xreadlines()]
            for result in results:
                for hash in hashes:
                    if result.split(":", 1)[1] in hash:
                        hashes.remove(hash)
            if not hashes:
                os.remove("%s/tmp/%s/hashes" %(home, self.id))
            else:
                os.remove("%s/tmp/%s/hashes" %(home, self.id))
                with open("%s/tmp/%s/hashes" %(home, self.id), "a") as f:
                    dico = "\n".join(hash for hash in hashes)
                    f.write(dico)
        except IOError as e:
            print e.message

    def work(self):
        if debug:
            print "MasterProtocol.work()"
        if self.factory.jobs.keys():
            if debug:
                print "    There is a task to perform"
            ind = random.randint(0, len(self.factory.jobs.keys())-1)
            key = self.factory.jobs.keys()[ind]
            if debug:
                print "    ID:", key
            if not self.factory.jobs[key]:
                if debug:
                    print "    No job for that key!"
                self.factory.jobs.pop(key)
                self.work()
                return
            job = self.factory.jobs[key].popleft()
            self.doJob(job)
            if not self.factory.jobs[key]:
                self.factory.jobs.pop(key)
        else:
            d = defer.Deferred()
            d.addCallback(self.doJob)
            peer = self.transport.getPeer()
            self.factory.deferreds["%s:%d" %(peer.host, peer.port)] = d

    def fire(self):
        if debug:
            print "MasterProtocol.fire()"
        if self.factory.deferreds and self.factory.jobs.keys():
            d = self.factory.deferreds.popitem()[1]
            ind = random.randint(0, len(self.factory.jobs.keys())-1)
            key = self.factory.jobs.keys()[ind]
            d.callback(self.factory.jobs[key].popleft())

    def addTask(self, type, chunk, father, hashtypes, id):
        if debug:
            print "MasterProtocol.addTask(%s)" %(id)
        job = Job(type, chunk, father, list(hashtypes), id)
        chunk = getChunk[type](chunk)
        toSend = [type, chunk, father, list(hashtypes), id]
        self.factory.api.sendPut("jobs", [toSend, id])
        if not id in self.factory.jobs.keys():
            self.factory.jobs[id] = deque()
        self.factory.jobs[id].append(job)
        if self.factory.deferreds:
            job = self.factory.jobs[id].popleft()
            d = self.factory.deferreds.popitem()[1]
            d.callback(job)

    def doJob(self, job):
        if debug:
            print "MasterProtocol.doJob(%s)" %(str(job))
        id = job.id
        if job.father in self.factory.fathers[id]:
            nb = self.factory.fathers[id].pop(job.father)
            self.factory.api.sendFather(job.father, nb, id)
        if debug:
            print "Step 1"
        chunk = getChunk[job.type](job.job)
        if debug:
            print "Step 2"
        self.job = job
        self.father = job.father
        if not id in self.factory.protocols:
            self.factory.protocols[id] = set()
        if debug:
            print "Step 3"
        self.factory.protocols[id].add(self)
        try:
            with open("%s/tmp/%s/hashes" %(home, id), "r") as f:
                hashes = [h.strip("\n") for h in f.xreadlines()]
            if debug:
                print "Step 4"
            toSend, empty = job.getOneJob()
            if debug:
                print "Step 5"
            if not empty:
                if not id in self.factory.jobs:
                    self.factory.jobs[id] = deque()
                if job in self.factory.jobs[id]:
                    self.factory.jobs[id].remove(job)
                self.factory.jobs[id].appendleft(job)
            if debug:
                print "Step 6"
            while hashes:
                if debug:
                    print "Step 7"
                self.sendPut("hashes", [hashes[:150], toSend[2]])
                hashes = hashes[150:]
            if debug:
                print "Step 8"
            toSend[1] = chunk
            self.sendDo(*toSend)
            if debug:
                print "Step 9"
            self.hashtype = toSend[2]
        except IOError as e:
            print e.message

    # ======================= END MISC FUNCTIONS ======================= #

class MasterFactory(object, protocol.ClientFactory, protocol.ServerFactory):

    def __init__(self, protocol=MasterProtocol):
        self.protocol = protocol
        self.protocols = dict()
        self.jobs = dict()
        self.fathers = dict()
        self.results = dict()
        self.hashes = dict()
        self.nbjobs = dict()
        self.type = type
        self.slavenodes = []
        self.api = None
        self.master = None
        self.secondary = None
        self.deferreds = dict()

factory = MasterFactory()
reactor.listenTCP(PORT, factory, interface=HOST)
reactor.connectTCP(api_host, api_port, factory)
reactor.run()
logger.write()
shutil.rmtree("%s/tmp"%home)
os.mkdir("%s/tmp"%home)
