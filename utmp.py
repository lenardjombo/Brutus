#!/usr/bin/env python
# -*- coding: utf-8 -*-

# simple utmp parser
# Reference
# http://man7.org/linux/man-pages/man5/utmp.5.html

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, time, datetime, sys, csv, argparse, struct, io, ipaddress

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

parser = argparse.ArgumentParser(description="utmp parser")
parser.add_argument("input", help="specified input utmp file")
parser.add_argument("-o", "--output", help="specified output file name")
args = parser.parse_args()

input_file = args.input
output_file = args.output

row = ["type", "pid", "line", "id", "user", "host", "term", "exit", "session", "sec", "usec", "addr"]

def parseutmp(utmp_filesize, utmp_file, tsv):

  STATUS = {
    0: 'EMPTY',
    1: 'RUN_LVL',
    2: 'BOOT_TIME',
    3: 'NEW_TIME',
    4: 'OLD_TIME',
    5: 'INIT',
    6: 'LOGIN',
    7: 'USER',
    8: 'DEAD',
    9: 'ACCOUNTING'}
        
  record_field = []

  offset = 0
  while offset < utmp_filesize:
    utmp_file.seek(offset)
    type = struct.unpack("<L", utmp_file.read(4))[0]
    for k, v in STATUS.items():
      if type == k:
        type = v
    pid = struct.unpack("<L", utmp_file.read(4))[0]
    line = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
    id = utmp_file.read(4).decode("utf-8", "replace").split('\0', 1)[0]
    user = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
    host = utmp_file.read(256).decode("utf-8", "replace").split('\0', 1)[0]
    term = struct.unpack("<H", utmp_file.read(2))[0]
    exit = struct.unpack("<H", utmp_file.read(2))[0]
    session = struct.unpack("<L", utmp_file.read(4))[0]
    sec = struct.unpack("<L", utmp_file.read(4))[0]
    sec = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(float(sec)))
    usec = struct.unpack("<L", utmp_file.read(4))[0]
    addr = ipaddress.IPv4Address(struct.unpack(">L", utmp_file.read(4))[0])
    record_field.extend([type, pid, line, id, user, host, term, exit, session, sec, usec, addr])        
    csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(record_field)
    record_field = []
    offset += 384
  utmp_file.close()

if __name__ == '__main__':
  if os.path.exists(input_file):
    with open(input_file, "rb") as utmp_file:
      utmp_filesize = os.path.getsize(input_file)
      if output_file:
          tsv = open(output_file, "w", encoding='UTF-8')
      else:
          tsv = sys.stdout
      csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row)
      parseutmp(utmp_filesize, utmp_file, tsv)
  else:
    print("No input file found")
  sys.exit(1)
