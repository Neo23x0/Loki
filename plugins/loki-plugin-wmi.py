# -*- coding: utf-8 -*-

"""
Loki WMI Scanner plugin
2018/04/20
2018/04/21
Author: @DidierStevens
"""

import hashlib
import sys

def ScanWMI():
    global logger  # logger is defined in loki.py.__main__

    if sys.platform in ("win32", "cygwin"):
        try:
            import wmi
        except ImportError:
            wmi = None
            logger.log("CRITICAL", "WMIScan", "Unable to import wmi")
            print("Unable to import wmi")
        oWMI = wmi.WMI(namespace=r'root\subscription')

        knownHashes = ['159e2bcde798cf5fbb290f90a7ccc1a6', '20d385446e60cf9134792d5b145c54bb', '65c80cb7a9094b32c3f9982887b9862a', '6ddb270d17551138747ad7c1bc3db9b3', 'de5b1c4f59c4463f8e9b70cbe1156976']
        
        leventFilter = []
        lFilterToConsumerBinding = []
        lCommandLineEventConsumer = []
        lActiveScriptEventConsumer = []
        try:
            leventFilter = oWMI.__eventFilter()
        except:
            logger.log("WARNING", "WMIScan", 'Error retrieving __eventFilter')
        try:
            lFilterToConsumerBinding = oWMI.__FilterToConsumerBinding()
        except:
            logger.log("WARNING", "WMIScan", 'Error retrieving __FilterToConsumerBinding')
        try:
            lCommandLineEventConsumer = oWMI.CommandLineEventConsumer()
        except:
            logger.log("WARNING", "WMIScan", 'Error retrieving CommandLineEventConsumer')
        try:
            lActiveScriptEventConsumer = oWMI.ActiveScriptEventConsumer()
        except:
            logger.log("WARNING", "WMIScan", 'Error retrieving ActiveScriptEventConsumer')

        for eventFilter in leventFilter:
            try:
                hashEntry = hashlib.md5(str(eventFilter)).hexdigest()
                if hashEntry not in knownHashes:
                    logger.log("WARNING", "WMIScan", 'CLASS: __eventFilter MD5: %s NAME: %s QUERY: %s' % (hashEntry, eventFilter.wmi_property('Name').value, eventFilter.wmi_property('Query').value))
            except:
                logger.log("INFO", "WMIScan", repr(str(eventFilter)))
        for FilterToConsumerBinding in lFilterToConsumerBinding:
            try:
                hashEntry = hashlib.md5(str(FilterToConsumerBinding)).hexdigest()
                if hashEntry not in knownHashes:
                    logger.log("WARNING", "WMIScan", 'CLASS: __FilterToConsumerBinding MD5: %s CONSUMER: %s FILTER: %s' % (hashEntry, FilterToConsumerBinding.wmi_property('Consumer').value, FilterToConsumerBinding.wmi_property('Filter').value))
            except:
                logger.log("INFO", "WMIScan", repr(str(FilterToConsumerBinding)))
        for CommandLineEventConsumer in lCommandLineEventConsumer:
            try:
                hashEntry = hashlib.md5(str(CommandLineEventConsumer)).hexdigest()
                if hashEntry not in knownHashes:
                    logger.log("WARNING", "WMIScan", 'CLASS: CommandLineEventConsumer MD5: %s NAME: %s COMMANDLINETEMPLATE: %s' % (hashEntry, CommandLineEventConsumer.wmi_property('Name').value, CommandLineEventConsumer.wmi_property('CommandLineTemplate').value))
            except:
                logger.log("INFO", "WMIScan", repr(str(CommandLineEventConsumer)))
        for ActiveScriptEventConsumer in lActiveScriptEventConsumer:
            logger.log("INFO", "WMIScan", repr(str(ActiveScriptEventConsumer)))


LokiRegisterPlugin("PluginWMI", ScanWMI, 1)  # noqa: F821 undefined name 'LokiRegisterPlugin'
