import sys
import os
import operator

LOKI_PHASE_BEFORE_SCANS = 1
LOKI_PHASE_AFTER_SCANS = 2
LOKI_PHASE_END = 3

FOLDER_PLUGINS = 'plugins'
FILENAME_LOKI_INIT = 'loki-init.py'

REGISTERED_PLUGINS = []

logger = None

def CheckLokiInit(applicationPath):
    pathLokiInit = os.path.join(applicationPath, FOLDER_PLUGINS, FILENAME_LOKI_INIT)
    statusLokiInit = 'notpresent'
    if os.path.exists(pathLokiInit):
        statusLokiInit = 'present'
    return pathLokiInit, statusLokiInit

class cRegisteredPlugin:
    def __init__(self, name, entrypoint, phase):
        self.name = name
        self.entrypoint = entrypoint
        self.phase = phase

def LokiRegisterPlugin(name, entrypoint, phase):
    global REGISTERED_PLUGINS
    global logger

    oRegisteredPlugin = cRegisteredPlugin(name, entrypoint, phase)
    REGISTERED_PLUGINS.append(oRegisteredPlugin)
    logger.log('NOTICE', 'Init', 'Registered plugin %s' % oRegisteredPlugin.name)

def RunPluginsForPhase(phase):
    global REGISTERED_PLUGINS
    global logger

    for oRegisteredPlugin in REGISTERED_PLUGINS:
        if oRegisteredPlugin.phase == phase:
            logger.log('NOTICE', 'Init', 'Running plugin %s' % oRegisteredPlugin.name)
            try:
                oRegisteredPlugin.entrypoint()
            except:
                logger.log('ERROR', 'Init', 'Error occured while running PLUGIN: %s ERROR: %s' % (oRegisteredPlugin.name, sys.exc_info()[1]))
            logger.log('NOTICE', 'Init', 'Finished running plugin %s' % oRegisteredPlugin.name)

# Load plugins if present (plugins/*.py)
def LoadPlugins(dGlobals, dLocals):
    global REGISTERED_PLUGINS
    global logger

    # get some objects from loki.py via globals()
    logger = dGlobals['logger']
    get_application_path = dGlobals['get_application_path']

    # load plugins
    plugins_dir = os.path.join(get_application_path(), FOLDER_PLUGINS)
    if os.path.exists(plugins_dir):
        for root, directories, files in os.walk(plugins_dir, followlinks=False):
            for file in files:
                if file.endswith('.py') and file != FILENAME_LOKI_INIT:
                    pluginFile = os.path.join(root, file)
                    try:
                        execfile(pluginFile, dGlobals, dLocals)
                        logger.log('NOTICE', 'Init', 'Loaded plugin %s' % pluginFile)
                    except:
                        logger.log('ERROR', 'Init', 'Failed to load PLUGIN: %s ERROR: %s' % (pluginFile, sys.exc_info()[1]))

    # sort plugins by name to have predictable execution order
    REGISTERED_PLUGINS = sorted(REGISTERED_PLUGINS, key=operator.attrgetter('name'))
