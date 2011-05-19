#!/usr/bin/env python

"""Module docstring.

This serves as a long usage message.
"""
import sys
import getopt
import re
import traceback
import logging
from optparse import OptionParser

def printProcessTree(pid, childDict, indent):
    for i in xrange(0, indent):
        print "   ",
    print pid
    for childPid in childDict[pid]:
        printProcessTree(childPid, childDict, indent+1)
    return

def processTree(syscallListByPid):
    childDict = {}
    headPids = set()

    for syscallList in syscallListByPid.values():    
        pid = (syscallList[0])["pid"]
        headPids.add(pid)    # remove if we find it come from clone
        childDict[pid] = list()
        for syscallLine in syscallList:
            if "syscall" in syscallLine and syscallLine["syscall"] == "clone":
                childDict[pid].append(syscallLine["return"])

    for childPidList in childDict.values():
        for childPid in childPidList:
            headPids.remove(childPid)
                
    for head in headPids:
        printProcessTree(head, childDict, 0)
                

########################################
fileStatList = {}
fidStatList = {}
def statFileIO(result):
    global fidStatList
    global fileStatList
    if result["syscall"] in ["read", "write", "open", "close"]:
        if result["return"] == -1:  # ignore failed syscalls
            return
        
        if result["syscall"] == "open":
            fid = result["return"]
        else:
            fid = result["args"][0]

        # file close
        if result["syscall"] == "close":
            if fid in fidStatList:
                #print fidStatList[fid]
                filename = fidStatList[fid][0]
                if filename not in fileStatList:
                    fileStatList[filename] = [1, fidStatList[fid][1], fidStatList[fid][2], fidStatList[fid][3], fidStatList[fid][4]]
                else:
                    fileStatList[filename][0] += 1
                    for i in [1, 2, 3, 4]:
                        fileStatList[filename][i] += fidStatList[fid][i]

                del fidStatList[fid]
                return

        # if read/write/open
        if fid not in fidStatList:
            if result["syscall"] == "open":
                # fidStatList[fid] = [filename, read count, read acc bytes, write count, write acc bytes]
                fidStatList[fid] = [result["args"][0], 0, 0, 0, 0]
            else:
                fidStatList[fid] = ["unknown:"+fid, 0, 0, 0, 0]

        # stat read/write
        if result["syscall"] == "read":
            fidStatList[fid][1] += 1
            fidStatList[fid][2] += int(result["return"])
        if result["syscall"] == "write":
            fidStatList[fid][3] += 1
            fidStatList[fid][4] += int(result["return"])
        return

def printFileIO():
    global fidStatList
    global fileStatList
    for fid in fidStatList:
        #print fidStatList[fid]
        filename = fidStatList[fid][0]
        if filename not in fileStatList:
            fileStatList[filename] = [1, fidStatList[fid][1], fidStatList[fid][2], fidStatList[fid][3], fidStatList[fid][4]]
        else:
            fileStatList[filename][0] += 1
            for i in [1, 2, 3, 4]:
                fileStatList[filename][i] += fidStatList[fid][i]

    for file in fileStatList:
        print file, ",",
        for item in fileStatList[file]:
            print item, ",",
        print

########################################

def straceParser(filename, havePid=0, haveTime=0, haveTimeSpent=0):
    syscallListByPid = {}

    unfinishedSyscallStack = {}
    f = open(filename, "r")
    if not f:
        logging.error("Cannot open file: " + filename)
        return

    for line in f:

        if line.find("restart_syscall") != -1:      # TODO: ignore this first
            continue

        if line.find("<unfinished ...>") != -1:     # store the unfinished line for reconstruct
            if havePid:
                pid = (line.partition(" "))[0]
                unfinishedSyscallStack[pid] = line
            else:
                unfinishedSyscallStack[0] = line
            continue

        if line.find("resumed>") != -1:         # get back the unfinished line and reconstruct
            if havePid:
                pid = (line.partition(" "))[0]
                if pid not in unfinishedSyscallStack:
                    continue                        # no <unfinished> line before, ignore
                existLine = unfinishedSyscallStack[pid]
            else:
                if 0 not in unfinishedSyscallStack:
                    continue                        # no <unfinished> line before, ignore
                existLine = unfinishedSyscallStack[0] 
            lineIndex = line.find("resumed>") + len("resumed>")
            line = existLine.replace("<unfinished ...>", line[lineIndex:])
            #print "debug reconstructed line:", line


        # Parse the line. The line should be a completed system call
        #print line
        result = parseLine(line, havePid, haveTime, haveTimeSpent)

        # put into syscallListByPid
        #if result["pid"] not in syscallListByPid:
        #    syscallListByPid[result["pid"]] = list()
        #syscallListByPid[result["pid"]].append(result)

        # hook here for every completed syscalls:
        if result:
            #print result
            statFileIO(result)
        
        #print result

    # hook here for final:
    printFileIO()

    return 

#
#   parseLine
#
#   It parse a complete line and return a dict with the following:
#   pid :       pid (if havePid enabled)
#   startTime : start time of the call (if haveTime enabled)
#   syscall :   system call function 
#   args :      a list of arguments ([] if no options)
#   return :    return value (number or '?' (e.g. exit syscall))
#   timeSpent : time spent in syscall (if haveTimeSpent enable. But even so, it may not exist in some case (e.g. exit syscall) )
#
#   Return null if hit some error
#
#   (Not implemented) signalEvent : signal event (no syscall, args, return)
#
def parseLine(line, havePid=0, haveTime=0, haveTimeSpent=0):
    result = {}    
    remainLine = line

    try:
        if havePid:
            m = re.match(r"(\d+)[ ]+(.*)", remainLine)
            result["pid"] = m.group(1)
            remainLine = m.group(2)
        if haveTime:
            m = re.match(r"([:.\d]+)[ ]+(.*)", remainLine)
            result["startTime"] = m.group(1)
            remainLine = m.group(2)

        if remainLine.find("--- SIG") != -1:        # a signal line
            #result["signalEvent"] = remainLine
            #return result
            ### Ignore signal line now
            return 
        
        ### assume no unfinished/resumed syscall, all are merged by caller
        if remainLine.find("<unfinished ...>") != -1 or remainLine.find("resumed>") != -1:
            return

        # normal system call
        m = re.match(r"([^(]+)\((.*)\)[ ]+=[ ]+([\d\-?]+)(.*)", remainLine)
        result["syscall"] = m.group(1)
        result["args"] = parseArgs(m.group(2).strip())
        result["return"] = m.group(3)
        remainLine = m.group(4)

        if haveTimeSpent:
            m = re.search(r"<([\d.]*)>", remainLine)
            if m:
                result["timespent"] = m.group(1)
            else:
                result["timespent"] = "unknown"

    except:
        logging.warning("parseLine: Error parsing this line: " + line)
        #print sys.exc_info()
        #exctype, value, t = sys.exc_info()
        #print traceback.print_exc()
        #print sys.exc_info()
        return 
        
    return result

def parseArgs(argString):
    endSymbol = {'{':'}', '[':']', '"':'"'}
    resultArgs = []
    currIndex = 0
    while currIndex < len(argString):
        if argString[currIndex] == ' ':     # ignore space
            currIndex += 1
            continue
        
        if argString[currIndex] in ['{', '[', '"']:

            searchEndSymbolStartAt = currIndex+1    # init search from the currIndex+1
            while searchEndSymbolStartAt < len(argString):
                endSymbolIndex = argString.find(endSymbol[argString[currIndex]], searchEndSymbolStartAt)
                if endSymbolIndex == -1:
                    logging.warning("parseArgs: strange, can't find end symbol in this arg:" + argString)
                    return []
                if argString[endSymbolIndex-1] == '\\' and (endSymbolIndex-2 >= 0 and argString[endSymbolIndex-2] != '\\'):  # escape char which are not escaped
                    searchEndSymbolStartAt = endSymbolIndex + 1
                else:
                    break
            searchCommaStartAt = endSymbolIndex + 1
        else:    # normal, search comma after currIndex
            searchCommaStartAt = currIndex + 1

        i = argString.find(',', searchCommaStartAt)
        if i == -1:
            i = len(argString)      # the last arg
        resultArgs.append(argString[currIndex:i]) # not include ','
        currIndex = i + 1           # point to the char after ','

    #print argString
    #print resultArgs
    return resultArgs

def main():
    # parse command line options
    optionParser = OptionParser()
    optionParser.add_option("-t", "--withtime", action="store_true", dest="withtime", help="have time in strace")
    optionParser.add_option("-f", "--withfork", action="store_true", dest="withpid", help="have pid in strace")
    optionParser.add_option("-T", "--withtimespent", action="store_true", dest="withtimespent", help="have time spent in strace")

    (options, args) = optionParser.parse_args()

    if len(args) < 1:
        print "Filename is missing, exit."
        return 1

    straceParser(args[0], options.withpid, options.withtime, options.withtimespent)

    #print syscallListByPid.keys()
    #processTree(syscallListByPid)

if __name__ == "__main__":
    main()
