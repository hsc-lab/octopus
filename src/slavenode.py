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
from params import slavenode as config
from params import charsets, api
from attacks import format, makeJob, attack
import attacks
import shutil
import os
import psutil
import urlparse
import urllib2
import json
import re
import logs
import optparse
#import zlib

OCTOPUS = """
  ___       _
 / _ \\  ___| |_ ___  _ __  _   _ ___
| | | |/ __| __/ _ \\| '_ \\| | | / __|
| |_| | (__| || (_) | |_) | |_| \\__ \\
 \\___/ \\___|\\__\\___/| .__/ \\__,_|___/
                    |_|
"""
print OCTOPUS
print "Slavenode started"

home = config["vars"]["HOME"]
regexes = config["regexes"]
program = config["program"]
vars = config["vars"]
api_host = api["host"]
api_port = api["port"]

logger = logs.Logger("%s/slave.log" %(home), reactor)


def parse_args():
    """
    Arguments parser
    """
    usage = """usage: %prog [options] hashesFile"""

    parser = optparse.OptionParser(usage)

    help = "Debug mode"
    parser.add_option("-d", "--debug", action = "store_true", help = help)

    options, args = parser.parse_args()
    return options

debug = parse_args().debug


def httprequest(data):
    #data = zlib.compress(data)
    if debug:
        print "httprequest(%s)" %(data)
    request = "GET /?cmd=%s HTTP/1.1\r\n" %urllib2.quote(data)
    request += "User-Agent: Octopus"
    return request


class SlaveProtocol(object, LineReceiver):
    delimiter = "\r\n\r\n"

    # ======================= PROTOCOL FUNCTIONS ======================= #
    def connectionMade(self):
        self.buffer = ""
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "Connection made with %s:%d" %(host, port)
        logger.log("Connection made with %s:%d"%(host, port))
        self.proto = {"NODETYPE": self.nodetype,
                        "LISTENING": self.listening,
                        "DO": self.do,
                        "PUT": self.put,
                        "GET": self.get,
                        "KICK": self.kick,
                        "ERROR": self.error,
                        "STOP": self.stop}
        self.nodes = {"api": self.api,
                        "master": self.master,
                        "secondary": self.secondary}
        self.putActions = {"file": self.putFile,
                            "hashes": self.putHashes}
        self.getActions = {"infos": self.getInfos}
        self.sendNodetype()

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        if debug:
            print "Connection lost with %s:%d"%(host, port)
        logger.log("Connection lost with %s:%d"%(host, port))
        if self == self.factory.master:
            self.factory.master = None
            if self.factory.ap:
                self.factory.ap.transport.signalProcess("KILL")
            self.factory.waiting = True
        elif self == self.factory.api:
            self.factory.api = None

    def lineReceived(self, data):
        if debug:
            print "SlaveProtocol.lineReceived(%s)" %(data)
        lines = data.split("\r\n")
        #request = dict()
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
            print "SlaveProtocol.requestReceived(%s)" %(data)
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        logger.log("Recv from %s:%d: %s"%(host, port, data))
        self.buffer += data
        try:
            cmd = json.loads(self.buffer)
        except ValueError as e:
            #self.sendError(str(e))
            return
        self.buffer = ""
        if cmd:
            if cmd[0] in self.proto.keys():
                try:
                    self.proto[cmd[0]](*cmd[1:])
                except TypeError as e:
                    self.sendError(str(e))
                    return
            else:
                self.sendError("Function %s() does not exist" %cmd[0].lower())

    def sendRequest(self, data):
        if debug:
            print "SlaveProtocol.sendRequest(%s)" %(data)
        peer = self.transport.getPeer()
        host, port = peer.host, peer.port
        logger.log("Sent to %s:%d: %s\n"%(host, port, data))
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
            print "SlaveProtocol.nodetype(%s)" %(type)
        self.nodes[type]()

    def listening(self, host, port):
        """
        Answer to a LISTENING command. Should tell clients or slavenodes what
        is the address of the current Masternode.
        """
        if debug:
            print "SlaveProtocol.listening(%s, %d)" %(host, port)
        if self.factory.master:
            self.factory.master.transport.loseConnection()
            self.factory.master = None
        reactor.connectTCP(host, port, self.factory)

    def do(self, type, job, hashtype):
        if debug:
            print "SlaveProtocol.do(%s, %s, %s)" %(type, str(job), hashtype)
        """
        Answer to a DO command. Used to send a job.
        """
        if self.factory.waiting:
            if debug:
                print "    I was waiting for a job... but not anymore :D"
            self.factory.waiting = False
            reg = regexes[program]
            if debug:
                print "    Using regex:", reg
            vars["JOB"] = makeJob[type][program](job)
            if debug:
                print "    vars[JOB] =", vars["JOB"]
            vars["HASHTYPE"] = attacks.hashtypes[hashtype][program]["id"]
            if debug:
                print "    vars[HASHTYPE] =", vars["HASHTYPE"]
            vars["d"], vars["l"] = charsets["d"], charsets["l"]
            vars["u"], vars["s"] = charsets["u"], charsets["s"]
            vars["a"] = charsets["a"]
            if debug:
                print "    Charsets set in vars"
            cmd = attack(program, type, vars)
            if debug:
                print "    Command:", cmd
            else:
                print "octopus_sh$", cmd
            self.factory.ap = AttackProtocol(reg, self)
            ap = self.factory.ap
            reactor.spawnProcess(ap, cmd.split()[0], cmd.split(), {})
            self.deferred = defer.Deferred()
            self.deferred.addCallback(self.sendResult)
            if debug:
                print "    Attack started!"
        else:
            print "    Still busy... Please wait! :v"
            self.sendWait()

    def put(self, type, objects):
        """
        Answer to a PUT command. Used to upload files such as dictionaries and
        hashfiles.
        """
        if debug:
            print "SlaveProtocol.put(%s, ...)" %(type)
        self.putActions[type](*objects)

    def get(self, type, objects):
        """
        Answer to a GET command. Used to get information about slavenodes and
        job requests (results, state).
        """
        if debug:
            print "SlaveProtocol.get(%s, ...)" %(type)
        self.getActions[type](*objects)

    def getInfos(self):
        if debug:
            print "SlaveProtocol.getInfos()"
        infos = dict()
        infos["cpu"] = str(psutil.cpu_percent(interval = 0))
        infos["program"] = program
        self.sendPut("infos", [infos])

    def api(self):
        """
        Answer to a NODETYPE api command. Sent by API when a connection
        is made.
        """
        if debug:
            print "SlaveProtocol.api()"
        self.factory.api = self

    def master(self):
        """
        Answer to a NODETYPE master command. Sent by Masternode when a
        connection is made.
        """
        if debug:
            print "SlaveProtocol.master()"
        self.factory.master = self

    def secondary(self):
        """
        Answer to a NODETYPE secondary command. Sent by Secondarynode when a
        connection is made.
        """
        if debug:
            print "SlaveProtocol.secondary()"
        self.factory.master = self

    def kick(self):
        if debug:
            print "SlaveProtocol.kick()"
        if self.factory.ap:
            self.factory.ap.transport.signalProcess("KILL")
        reactor.stop()

    def putFile(self, chunk, path):
        """
        Answer to a PUT dictionary command. Used to store a dictionary.
        """
        pass

    def putHashes(self, hashes, type):
        """
        Answer to a PUT hashes command. Used to store a hashfile.
        """
        if debug:
            print "SlaveProtocol.putHashes(%s, %s)" %(str(hashes[:3]), type)
        if not self.factory.waiting:
            self.sendError("Hashes are being used")
            return
        #self.hashes = set()
        with open("%s/tmp/hashes" %home, "a") as f:
            formatted = []
            for hash in hashes:
                fo = format(hash, type, program)
                if fo:
                    formatted.append(fo)
            dico = "\n".join(formatted)
            f.write(dico + "\n")

    def error(self, msg):
        print "Error:", msg

    def stop(self):
        if self.factory.ap:
            self.factory.ap.transport.signalProcess("KILL")
        self.factory.waiting = True

    # ======================= END RECV FUNCTIONS ======================= #

    # ========================= SEND FUNCTIONS ========================= #
    def sendNodetype(self):
        if debug:
            print "SlaveProtocol.sendNodetype()"
        self.sendRequest(json.dumps(["NODETYPE", "slave"]))

    def sendOK(self, msg):
        if debug:
            print "SlaveProtocol.sendOK(%s)" %(msg)
        self.sendRequest(json.dumps(["OK", msg]))

    def sendError(self, msg):
        if debug:
            print "SlaveProtocol.sendError(%s)" %(msg)
        self.sendRequest(json.dumps(["ERROR", msg]))

    def sendPut(self, type, object):
        if debug:
            print "SlaveProtocol.sendPut(%s, ...)" %(type)
        self.sendRequest(json.dumps(["PUT", type, object]))

    def sendResult(self, results):
        if debug:
            print "SlaveProtocol.sendResult(%s)" %(str(results[:3]))
        os.remove("%s/tmp/hashes" %(home))
        self.factory.ap = None
        master = self.factory.master
        while len(results) > 50:
            master.sendRequest(json.dumps(["RESULTP", results[:50]]))
            results = results[50:]
        master.sendRequest(json.dumps(["RESULT", results]))
        self.factory.waiting = True

    def sendWait(self):
        if debug:
            print "SlaveProtocol.sendWait()"
        self.sendRequest(json.dumps(["WAIT"]))

    # ======================= END SEND FUNCTIONS ======================= #

class AttackProtocol(protocol.ProcessProtocol):

    def __init__(self, reg, proto):
        self.data = ""
        self.err = ""
        self.reg = reg
        self.proto = proto
        self.waiting = True

    def outReceived(self, data):
        if debug:
            print "AttackProtocol.outReceived(%s)" %(data)
        self.data += data

    def format(self, data):
        if debug:
            print "AttackProtocol.format(%s)" %(data)
        rdata = data
        if self.reg[1]:
            exp1 = self.reg[0]
            exp2 = self.reg[1]
            rdata= re.sub(exp1, exp2, rdata.strip("\n"))
            rdata = rdata.replace(" ", "")
        return rdata

    def errReceived(self, err):
        if debug:
            print "AttackProtocol.errReceived(%s)" %(err)
        self.err = self.err + err

    def outConnectionLost(self):
        if debug:
            print "AttackProtocol.outConnectionLost()"
        print self.data
        data = []
        lines = self.data.splitlines()
        for line in lines:
            if re.match(self.reg[0], line):
                data.append(self.format(line))
        d = self.proto.deferred
        d.callback(data)

    def errConnectionLost(self):
        pass


class SlaveFactory(object, protocol.ClientFactory, protocol.ServerFactory):

    def __init__(self, protocol=SlaveProtocol):
        self.protocol = protocol
        self.api = None
        self.master = None
        self.deferred = defer.Deferred()
        self.waiting = True
        self.ap = None

factory = SlaveFactory()
reactor.connectTCP(api_host, api_port, factory)
reactor.run()
logger.write()
shutil.rmtree("%s/tmp"%home)
os.mkdir("%s/tmp"%home)
