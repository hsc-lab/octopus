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

import time
import os


class Logger(object):

    def __init__(self, logfile, reactor):
        self.logfile = logfile
        if not os.path.isdir(os.path.dirname(self.logfile)):
            os.mkdir(os.path.dirname(self.logfile))
        self.reactor = reactor
        self._buffer = []
        self.write()

    def log(self, msg):
        day = time.strftime("%d/%m/%Y-%H:%M", time.localtime())
        if len(msg) < 200:
            self._buffer.append("[%s] %s" %(day, msg))
        else:
            msg = msg[0:40] + "..." + msg[-40:]
            self._buffer.append("[%s] %s" %(day, msg))

    def write(self):
        if self._buffer:
            with open(self.logfile, "a") as f:
                f.write("\n".join(self._buffer))
                f.write("\n")
                self._buffer = []
        self.reactor.callLater(15, self.write)
