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

import json
import sqlite3
import os


alpha = 0.05


class MatrixError(Exception):
    pass


class Matrix(object):

    def __init__(self, home, attack, height=101, width=None):
        self.home = home
        self.attack = attack
        self.av = [0 for i in range(height)]
        if width:
            self.__matrix = [[0]*width for i in range(height)]
            self.height = height
            self.width = width
        else:
            self.__matrix = [[0]*height for i in range(height)]
            self.height = height
            self.width = height
        self.identity()
        if not os.path.isfile("%s/matrices.db" %(home)):
            self.con = sqlite3.connect("%s/matrices.db" %(home))
            self.con.isolation_level = None
            self.cur = self.con.cursor()
            req = "CREATE TABLE matrices(attack primary key, matrix);"
            self.cur.execute(req)
        else:
            self.con = sqlite3.connect("%s/matrices.db" %(home))
            self.con.isolation_level = None
            self.cur = self.con.cursor()
        att = json.dumps(attack)
        req = "SELECT matrix FROM matrices WHERE attack='%s';" %(att)
        self.cur.execute(req)
        fetch = self.cur.fetchall()
        if fetch:
            self.__matrix = json.loads(fetch[0][0])

    def __getitem__(self, ij):
        return self.__matrix[ij[0]][ij[1]]

    def __setitem__(self, ij, val):
        self.__matrix[ij[0]][ij[1]] = val
        s = [self.__matrix[ij[0]][k]*k for k in range(self.width)]
        self.av[ij[0]] = sum(s)

    def __str__(self):
        s = ""
        maxlen = 0
        for mi in self.__matrix:
            for mij in mi:
                if len(str(mij)) > maxlen:
                    maxlen = len(str(mij))
        for mi in self.__matrix:
            for mij in mi:
                s += " "*(maxlen-len(str(mij))) + str(mij) + "  "
            s = s[:-2]
            s += "\n"
        s = s[:-1]
        return s

    def identity(self):
        for i in range(self.height):
            for j in range(self.width):
                if i == j:
                    self.__matrix[i][j] = 1
                else:
                    self.__matrix[i][j] = 0

    def save(self):
        home = self.home
        if not os.path.isfile("%s/matrices.db" %(home)):
            self.con = sqlite3.connect("%s/matrices.db" %(home))
            self.con.isolation_level = None
            self.cur = self.con.cursor()
            req = "CREATE TABLE matrices(attack primary key, matrix);"
            self.cur.execute(req)
        else:
            self.con = sqlite3.connect("%s/matrices.db" %(home))
            self.con.isolation_level = None
            self.cur = self.con.cursor()
        req = "REPLACE INTO matrices(attack, matrix) VALUES (?, ?);"
        args = (json.dumps(self.attack), json.dumps(self.__matrix))
        self.cur.execute(req, args)

    def update(self, i, j):
        for kj in range(i, 101):
            if kj == j:
                self[i, kj] = self[i, kj]*(1-alpha) + alpha
            else:
                self[i, kj] = self[i, kj]*(1-alpha)


def sum(nbs):
    accu = 0
    for nb in nbs:
        accu += nb
    return accu


def E(att, i):
    if len(att) == 1:
        return int(att[0].av[i])
    else:
        return E(att[1:], int(att[0].av[i]))
