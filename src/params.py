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

# List of regexes for every program. The first regex matches results, the
# second one makes result match the pattern "<hash/username>:<password>"
#
# For example: "hsc       (hduser)" should become "hduser:hsc"

regexes = {"john": (r"^([^\s]+)\s+\(([^\s]+)\)$", r"\2:\1"),
        "hashcat": (r"^([0-9a-zA-Z\./$]+):([^\s]+)", r"\2:\1")}

# Paths
octopath = "/app/octopus"
dictpath = octopath + "/tests/dictionaries"

# Local variables for every kind of node
api_vars = {"PROGS": octopath + "/progs",
                "HOME": octopath + "/tests/api"}

master_vars = {"PROGS": octopath + "/progs",
                "HOME": octopath + "/tests/master"}

secondary_vars = {"PROGS": octopath + "/progs",
                "HOME": octopath + "/tests/secondary"}

slave_vars = {"PROGS": octopath + "/progs",
                "HOME": octopath + "/tests/slave"}

# Charsets (lowercase, uppercase, digits, special and all)
charsets = {"l": "abcdefghijklmnopqrstuvwxyz",
            "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "d": "0123456789",
            "s": "!\"#$%&'()*+,-./:;=?@[\\]^_`{|}~"}
charsets["a"] = charsets["l"] + charsets["u"] + charsets["d"] + charsets["s"]

# Classification of attack types
att_types = {"dictionary": "dictionary",
                "toggle_case": "dictionary",
                "mask": "mask",
                "lookup_table": "dictionary",
                "combination": "dictionary",
                "permutation": "dictionary"}

# Configuration dictionaries for every node type
api = {"host": "localhost", "port": 4488, "vars": api_vars}

masternode = {"host": "localhost", "port": 4444, "vars": master_vars,
                "wordsbynode": 200}

secondarynode = {"host": "localhost", "port": 8888, "vars": secondary_vars,
                    "wordsbynode": 200}

slavenode = {"host": "localhost", "port": 4444, "regexes": regexes,
                "vars": slave_vars, "program": "hashcat"}
