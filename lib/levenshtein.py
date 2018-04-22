#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Levenshtein related functions

CHECK_FILES = ['svchost.exe', 'explorer.exe', 'iexplore.exe', 'lsass.exe', 'chrome.exe', 'csrss.exe', 'firefox.exe',
               'winlogon.exe']

class LevCheck():

    def __init__(self):
        pass

    def check(self, fileName):
        """
        Check if file name is very similar to a file in the check list
        :param fileName:
        :return:
        """
        for checkFile in CHECK_FILES:
            if levenshtein(checkFile, fileName) == 1:
                return checkFile
        return None

def levenshtein(s, t):
    if s == t: return 0
    elif len(s) == 0: return len(t)
    elif len(t) == 0: return len(s)
    v0 = [None] * (len(t) + 1)
    v1 = [None] * (len(t) + 1)
    for i in range(len(v0)):
        v0[i] = i
    for i in range(len(s)):
        v1[0] = i + 1
        for j in range(len(t)):
            cost = 0 if s[i] == t[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        for j in range(len(v0)):
            v0[j] = v1[j]

    return v1[len(t)]

