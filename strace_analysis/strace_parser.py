#!/usr/bin/env python

"""Module docstring.

This serves as a long usage message.
"""
import sys
import getopt
import re

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
                


def parser(filename):
    syscallListByPid = {}

    unfinishedSyscallStack = {}
    f = open(filename, "r")
    for line in f:

        havePid = 1
        haveTime = 1

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
        result = parseLine(line, havePid, haveTime)

        # put into syscallListByPid
        if result["pid"] not in syscallListByPid:
            syscallListByPid[result["pid"]] = list()
        syscallListByPid[result["pid"]].append(result)
        
        #print result

    return syscallListByPid

#
#   parseLine
#
#   It parse a line and return a dict with the following:
#   pid :       pid
#   startTime : start time of the call
#   syscall :   system call function
#   args :      a list of arguments
#   return :    return value
#   (ignore)signalEvent : signal event (no syscall, args, return)
#
def parseLine(line, havePid=0, haveTime=0):
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

        #if remainLine.find("--- SIG") != -1:        # a signal line
        #    result["signalEvent"] = remainLine
        #    return result
        
        if remainLine.find("<unfinished ...>") == -1:
            if remainLine.find("resumed>") == -1:
                # normal system call
                m = re.match(r"([^(]+)\((.*)\)[ ]+=[ ]+(.*)", remainLine)
                result["syscall"] = m.group(1)
                result["args"] = parseArgs(m.group(2).strip())
                result["return"] = m.group(3)
            else: # resume system call
                m = re.match(r"(.*)\)[ ]+=[ ]+(.*)", remainLine)
                result["args"] = m.group(1)
                result["return"] = m.group(2)

        else:   # unfinished system call
            m = re.match(r"([^(]+)\((.*)<unfinished ...>$", remainLine)
            result["syscall"] = m.group(1)
            result["args"] = (m.group(2)).split(", ")
            result["return"] = ""
    except:
        print "Error parsing this line: ", line
        print sys.exc_info()
        
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
                    print "parseArgs: strange, can't find end symbol in this arg:", argString
                    return []
                if argString[endSymbolIndex-1] == '\\':  # escape char
                    searchEndSymbolStartAt = endSymbolIndex+1
                else:
                    break
            searchCommaStartAt = endSymbolIndex+1
        else:    # normal, search comma after currIndex
            searchCommaStartAt = currIndex+1

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
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)
    # process options
    for o, a in opts:
        if o in ("-h", "--help"):
            print __doc__
            sys.exit(0)
    # process arguments
    #for arg in args:
    #    process(arg) # process() is defined elsewhere

    syscallListByPid = parser("test/stardict.out")

    print syscallListByPid.keys()
    processTree(syscallListByPid)

if __name__ == "__main__":
    main()
