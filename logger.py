from enum import Enum # For the log types


logTypes = Enum('LogTypes',['SUCCESS', 'INFO', 'WARNING', 'DEBUG', 'ERROR'])

# Verbose print manager
class Logger:
    verbose = False
    def __init__(self, verbose:bool):
        self.verbose = verbose
        
    def vprint(self, type: logTypes, message: str):
        if self.verbose or type == logTypes.ERROR or type == logTypes.SUCCESS  : # Only print if verbose is enabled or if its an error message
            resetColour = '\033[0m'
            logColour = ''
            typeName = type.name
            if typeName == 'SUCCESS':
                logColour = '\033[92m'
                pass
            if typeName == 'INFO':
                logColour = '\033[94m'
                pass
            if typeName == 'WARNING':
                logColour = '\033[93m'
                pass
            if typeName == 'DEBUG':
                logColour = '\033[95m'
                pass
            if typeName == 'ERROR':
                logColour = '\033[91m'
                pass

            verboseMessage = f'{logColour}[{typeName :^16}] {resetColour}: {message}'
            print(verboseMessage)