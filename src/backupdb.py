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

import sqlite3
from collections import deque
from params import octopath as home
import os
import json


class Job(object):

    def __init__(self, type, job, hshtypes, id):
        self.type = type
        self.job = job
        self.hashtypes = hshtypes
        self.id = id

    def __eq__(self, other):
        sameType = self.type == other.type
        sameJob = self.job == other.job
        sameId = self.id == other.id
        return sameType and sameJob and sameId

    def __ne__(self, other):
        diffType = self.type != other.type
        diffJob = self.job != other.job
        diffId = self.id != other.id
        return diffType or diffJob or diffId

    def getJob(self):
        type, job, hshtypes, id = self.type, self.job, self.hashtypes, self.id
        return [type, job, hshtypes, id]

    def getOneJob(self):
        try:
            type, job, hashtype = self.type, self.job, self.hashtypes.pop()
            id, empty = self.id, len(self.hashtypes)==0
            return [type, job, hashtype, id], empty
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


def dumpJobs(jobs):
    result = deque()
    for job in jobs:
        result.append(job.getJob())
    result = json.dumps(list(result))
    return result


class BackupDB(object):

    def __init__(self, apifactory, reactor, dbpath=None):
        self.factory = apifactory
        self.reactor = reactor
        self.dbpath = dbpath
        self.makedb()

    def makedb(self):
        if self.dbpath:
            self.con = sqlite3.connect(self.dbpath)
            self.con.isolation_level = None
            self.cur = self.con.cursor()
        else:
            try:
                os.remove("%s/backup.db" %(home))
            except OSError:
                pass
            self.con = sqlite3.connect("%s/backup.db" %(home))
            self.con.isolation_level = None
            self.cur = self.con.cursor()
            req = "CREATE TABLE hashes(id primary key, hashes);"
            self.cur.execute(req)
            req = "CREATE TABLE results(id primary key, results);"
            self.cur.execute(req)
            req = "CREATE TABLE jobs(id primary key, jobs);"
            self.cur.execute(req)
            req = "CREATE TABLE infos(id primary key, stime, etime, nbfound, "
            req += "nbpass, nbdone, nbjobs, how);"
            self.cur.execute(req)

    def save(self):
        jobs = self.factory.jobs
        hashes = self.factory.hashes
        results = self.factory.results
        infos = self.factory.infos
        infosEnded = self.factory.infosEnded
        # Save jobs
        for id in jobs.keys():
            req = "REPLACE INTO jobs(id, jobs) VALUES (?, ?);"
            jobsid = dumpJobs(jobs[id])
            args = (id, jobsid)
            self.cur.execute(req, args)
        # Save hashes
        for id in hashes.keys():
            req = "REPLACE INTO hashes(id, hashes) VALUES (?, ?);"
            hashesid = json.dumps(list(hashes[id]))
            args = (id, hashesid)
            self.cur.execute(req, args)
        # Save results
        for id in results.keys():
            req = "REPLACE INTO results(id, results) VALUES (?, ?);"
            resultsid = json.dumps(list(results[id]))
            args = (id, resultsid)
            self.cur.execute(req, args)
        # Save infos
        for id in infos:
            info = infos[id].getInfos()
            stime = info["stime"]
            nbfound = info["nbfound"]
            nbpass = info["nbpass"]
            nbdone = info["nbdone"]
            nbjobs = info["nbjobs"]
            req = "REPLACE INTO infos(id, stime, nbfound, nbpass, nbdone, nbjo"
            req += "bs) VALUES (?, ?, ?, ?, ?, ?);"
            args = (id, stime, nbfound, nbpass, nbdone, nbjobs)
            self.cur.execute(req, args)
        for id in infosEnded:
            info = infosEnded[id].getInfos()
            stime = info["stime"]
            etime = info["etime"]
            nbfound = info["nbfound"]
            nbpass = info["nbpass"]
            nbdone = info["nbdone"]
            nbjobs = info["nbjobs"]
            how = info["how"]
            req = "REPLACE INTO infos(id, stime, etime, nbfound, nbpass, nbdon"
            req += "e, nbjobs, how) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
            args = (id, stime, etime, nbfound, nbpass, nbdone, nbjobs, how)
            self.cur.execute(req, args)

    def autosave(self):
        print "Autosaving..."
        self.save()
        print "Autosaved!"
        self.reactor.callLater(300, self.autosave)

    def getJobs(self):
        req = "SELECT * FROM jobs;"
        self.cur.execute(req)
        listjobs = self.cur.fetchall()
        rjobs = dict()
        for jobs in listjobs:
            id = jobs[0]
            jobs = [Job(*j) for j in json.loads(jobs[1])]
            rjobs[id] = deque(jobs)
        return rjobs

    def getHashes(self):
        req = "SELECT * FROM hashes;"
        self.cur.execute(req)
        listhashes = self.cur.fetchall()
        rhashes = dict()
        for hashes in listhashes:
            id = hashes[0]
            hashes = json.loads(hashes[1])
            rhashes[id] = hashes
        return rhashes

    def getResults(self):
        req = "SELECT * FROM results;"
        self.cur.execute(req)
        listresults = self.cur.fetchall()
        rresults = dict()
        for results in listresults:
            id = results[0]
            results = json.loads(results[1])
            rresults[id] = set(results)
        return rresults

    def getInfos(self):
        req = "SELECT id, stime, etime, nbfound, nbpass, nbdone, nbjobs, how "
        req += "FROM infos;"
        self.cur.execute(req)
        listinfos = self.cur.fetchall()
        infos, infosEnded = {}, {}
        for info in listinfos:
            id = info[0]
            stime = info[1]
            etime = info[2]
            nbfound = info[3]
            nbpass = info[4]
            nbdone = info[5]
            nbjobs = info[6]
            how = info[7]
            if how:
                info = dict()
                info["stime"] = stime
                info["etime"] = etime
                info["nbfound"] = nbfound
                info["nbpass"] = nbpass
                info["nbdone"] = nbdone
                info["nbjobs"] = nbjobs
                info["how"] = how
                infosEnded[id] = InfoJob(**info)
            else:
                info = dict()
                info["stime"] = stime
                info["etime"] = etime
                info["nbfound"] = nbfound
                info["nbpass"] = nbpass
                info["nbdone"] = nbdone
                info["nbjobs"] = nbjobs
                infos[id] = InfoJob(**info)
        return infos, infosEnded

    def resume(self, id):
        infos = dict()
        hashes = []
        results = set()
        jobs = deque()
        req = "SELECT hashes FROM hashes WHERE id=\"%s\";" %(id)
        self.cur.execute(req)
        fetch = self.cur.fetchall()
        if fetch:
            hashes = json.loads(fetch[0][0])
        req = "SELECT jobs FROM jobs WHERE id=\"%s\";" %(id)
        self.cur.execute(req)
        fetch = self.cur.fetchall()
        if fetch:
            jobs = deque(json.loads(fetch[0][0]))
        req = "SELECT results FROM results WHERE id=\"%s\";" %(id)
        self.cur.execute(req)
        fetch = self.cur.fetchall()
        if fetch:
            results = set(json.loads(fetch[0][0]))
        req = "SELECT stime, nbfound, nbpass, nbdone, nbjobs, how "
        req += "FROM infos WHERE id=\"%s\";" %(id)
        self.cur.execute(req)
        fetch = self.cur.fetchall()
        if fetch:
            listinfos = fetch[0]
            stime = listinfos[0]
            nbfound = listinfos[1]
            nbpass = listinfos[2]
            nbdone = listinfos[3]
            nbjobs = listinfos[4]
            how = listinfos[5]
            if how != "stopped":
                return [], deque(), set(), dict()
            else:
                infos["stime"] = stime
                infos["etime"] = None
                infos["nbfound"] = nbfound
                infos["nbpass"] = nbpass
                infos["nbdone"] = nbdone
                infos["nbjobs"] = nbjobs
                infos["how"] = None
        return hashes, jobs, results, infos

    def init(self):
        hashes = self.getHashes()
        jobs = self.getJobs()
        results = self.getResults()
        infos, infosEnded = self.getInfos()
        self.factory.hashes = hashes
        self.factory.jobs = jobs
        self.factory.results = results
        self.factory.infos = infos
        self.factory.infosEnded = infosEnded
        for id in infos.keys():
            self.factory.nbjobs[id] = infos[id].nbjobs
        for id in infosEnded.keys():
            self.factory.nbjobs[id] = infosEnded[id].nbjobs
        self.autosave()
