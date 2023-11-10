# Imports 
import argparse
import os # For parsing the arguments and File System Directory management
import requests # For making the requests
from bs4 import BeautifulSoup # For parsing the html
import re # For the regex
import googlemaps # For the google maps api
from decouple import config # for .env file and environment variables
import uuid # For generating a unique id for each scan
import concurrent.futures # For multi threading
from multiprocessing import Pool

# Custom imports
from addressHandler import AddressHandler

# LOGGING
from logger import Logger, logTypes

# LOGO
LOGO_OSLFP = r"""         
 ▒█████    ██████  ██▓      █████▒██▓███  
▒██▒  ██▒▒██    ▒ ▓██▒    ▓██   ▒▓██░  ██▒
▒██░  ██▒░ ▓██▄   ▒██░    ▒████ ░▓██░ ██▓▒
▒██   ██░  ▒   ██▒▒██░    ░▓█▒  ░▒██▄█▓▒ ▒
░ ████▓▒░▒██████▒▒░██████▒░▒█░   ▒██▒ ░  ░
░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░ ▒░▓  ░ ▒ ░   ▒▓▒░ ░  ░
  ░ ▒ ▒░ ░ ░▒  ░ ░░ ░ ▒  ░ ░     ░▒ ░     
░ ░ ░ ▒  ░  ░  ░    ░ ░    ░ ░   ░░       
    ░ ░        ░      ░  ░                                                                                       
"""

class OpenSourceLocationFingerPrint():
    logger = None # Verbose output
    scanID = uuid.uuid4() # The unique id for the scan
    # self.scanID = # Generate a unique id for the scan

    # Web Scraping Vars
    entryUrl = [] # The url's to start the search from
    searchUrlSet = set() # The set of urls that have been searched
    depth = 3 # The depth of the search
    sameDomain = True # Only search the same domain
    vulnScan = True # Scan the location for security vulnerabilities
    placeslimit = 5 # The number of places to search for

    # AiVulnScan Vars
    aiMetaData = None # The meta data for the ai vuln scan tuple[scanlimit, min-confidence]
    # Address Vars
    addressSet = set() # List of known address Set
    knownLocations = [] # List of known locations with Address handler

    # Google Maps Vars
    googleMapsAPIKey = None # The google maps api key
    googleMapsClient = None # The google maps client

    def __init__(self):
        self.logger = Logger(args.verbose)
        self.depth = args.depth
        self.sameDomain = args.no_relm
        self.vulnScan = args.no_vuln
        self.placeslimit = args.placeslimit
        self.setUpGoogleMapsAPI() # Get the google maps api key
        
        self.aiMetaData = (args.scanlimit, args.confidence)

        self.logger.vprint(logTypes.INFO, 'Starting Open Source Location FingerPrint: scanID: {}'.format(self.scanID))

        # Get the Url from the user if its supplies as an argument and strip the quotes if they are there
        if args.url:
            for url in args.url:

                entryPoint = {"url": f"{url}".strip("'"), "level": 0, "scanned": False}
                # Check if the url is valid
                if not re.match(r'^https?://', entryPoint['url']):
                    self.logger.vprint(logTypes.WARNING, f'{url}: is not a valid url, you must include http(s)://.. skipping')
                    continue
                # Check if the url has already been added
                if entryPoint['url'] not in self.searchUrlSet:
                    self.logger.vprint(logTypes.SUCCESS, f'Adding url: {url} to the list of entry points')
                    self.searchUrlSet.add(entryPoint['url'])
                    self.entryUrl.append(entryPoint)
        else:
            self.logger.vprint(logTypes.WARNING, 'No url was specified, you can specify a url using the -u or --url argument')

        # Get the address from the user if its supplies as an argument and strip the quotes if they are there
        if args.address:
            for address in args.address:
                if address not in self.addressSet:
                    self.logger.vprint(logTypes.SUCCESS, f'Adding address: {address} to the list of known locations')
                    self.addressSet.add(address.strip("'"))
             
        
        if not self.entryUrl and not self.addressSet:
            self.logger.vprint(logTypes.ERROR, 'No url entry point or known location were specified, please specify either a --url or a --address')
            exit(1)

        # Find the locations from the url and add them to the list of known locations - This will also scan nested urls (depth)
        if not self.entryUrl:
            self.logger.vprint(logTypes.INFO, 'No url entry point was specified, skipping url search')
        else:
            self.findLocationFromURLs()

        if not self.addressSet:
            self.logger.vprint(logTypes.ERROR, 'No known locations were specified or found, please specify either a --url or a --address')
            exit(1)
        else :
            self.findLocationFromAddress()

        # Scan the locations for vulnerabilities
        self.scanLocationForVulnerabilities()

        # Generate a report
        self.generateReport()

        # Done 
        self.logger.vprint(logTypes.SUCCESS, f'All Done!')


    def findLocationFromURLs(self):
        # Loop through the entry points
        def processUrl(entryPoint):
            # for entryPoint in self.entryUrl:
            if entryPoint['scanned']:
                self.logger.vprint(logTypes.DEBUG, f'Url: {entryPoint["url"]} has already been scanned, skipping')
                return
            # Check if we need to keep track of the same root level domain (relm)
            rootDomain = None
            if self.sameDomain:
                rootDomain = entryPoint['url'].split('/')[2]
                self.logger.vprint(logTypes.INFO, f'Root level domain: {rootDomain}')
            # Check if the depth has been reached
            if entryPoint['level'] <= self.depth:
                self.logger.vprint(logTypes.INFO, f'Finding locations from the following url: {entryPoint["url"]}')
                # Make the request
                res = requests.get(entryPoint['url'])
                # res = requests.get("https://www.abertay.ac.uk")
                # Check if the request was successful
                if res.status_code == 200:
                    self.logger.vprint(logTypes.INFO, f'Successfully found the following url: {entryPoint["url"]}')
                    # Parse the html
                    soup = BeautifulSoup(res.text, 'html.parser')
                    self.findLocationAddressFromSite(soup)
                    # Find all the a tags
                    for link in soup.find_all('a'):
                        # Check if the link is a valid url
                        if link.get('href') and link.get('href').startswith('http'):
                            # Add the url to the list of entry points
                            self.addNewEntryPoint(link.get('href'), entryPoint['level'] + 1, relm=rootDomain)
                    # Mark the url as scanned
                    entryPoint['scanned'] = True
                else:
                    self.logger.vprint(logTypes.ERROR, f'Failed to find the following url: {entryPoint["url"]}')           
            else:
                self.logger.vprint(logTypes.DEBUG, f'Depth limit reached, skipping url: {entryPoint["url"]}')

        # use a thread pool to process the urls
        executor = concurrent.futures.ThreadPoolExecutor(10)  # Thread pool of 10
        futures = [executor.submit(processUrl, entryPoint) for entryPoint in self.entryUrl] # Start the load operations and mark each future with its URL
        concurrent.futures.wait(futures) # Wait for all the futures to finish


    def findLocationFromAddress(self):
          self.logger.vprint(logTypes.INFO, f'Finding locations from the following address: {self.addressSet}')
          # pass the address to the address handler that will get information such as geocode from the address and satalite image
          for address in self.addressSet:
              self.knownLocations.append(AddressHandler(address, self.googleMapsClient, self.logger, self.aiMetaData, nearbyPlacesLimit=self.placeslimit, scanid=self.scanID))
              pass

    def addNewEntryPoint(self, url: str, level: int, relm: str = None):
        # Check if the url is in the same relm
        if self.sameDomain:
            if relm:
                if relm not in url:
                    self.logger.vprint(logTypes.DEBUG, f'Url: {url} is not in the same relm, skipping')
                    return False
            else:
                self.logger.vprint(logTypes.WARNING, 'No relm was specified, skipping')
                return False
        if url in self.searchUrlSet:
            self.logger.vprint(logTypes.DEBUG, f'Url: {url} has already been added, skipping')
            return False
        newEntryPoint = {"url": url, "level": level, "scanned": False}
        self.searchUrlSet.add(url)
        self.entryUrl.append(newEntryPoint)   
        self.logger.vprint(logTypes.INFO, f'Adding nested url: {url} to the list of entry points. Level: {level}')
        return True
    
    def findLocationAddressFromSite(self, soup: BeautifulSoup):
        # Find all address tags in the html
        addressFound = []
        # Via the address tag
        addressTags = soup.find_all('address')
        if len(addressTags) == 0:
            self.logger.vprint(logTypes.WARNING, 'No address tags were found in the html')
        
        else: 
            for address in addressTags:
                #  Format the address found
                addressFound.append(" ".join(address.text.split()))

        # TODO: Find other ways to find the address on the site
        # DNS Recon SOA records?
        # Whois?
        # Maltego?
        
        for address in addressFound:
            # Check if the address is in the list of known locations
            if address not in self.addressSet:
                self.logger.vprint(logTypes.SUCCESS, f'Found new location: {address}')
                self.addressSet.add(address)
            else:
                self.logger.vprint(logTypes.DEBUG, f'Location: {address} has already been added, skipping')

       

    # Scan the locations for vulnerabilities 
    def scanLocationForVulnerabilities(self):
        if not self.vulnScan:
            self.logger.vprint(logTypes.WARNING, 'Skipping location scans for vulnerabilities')
            return False
        self.logger.vprint(logTypes.INFO, 'Starting location scan for vulnerabilities')
        '''
        Each of the vulnerabilities will be checked for by default, but can be specified by the user
        Vulnerabilities to check for:
        - Cameras nearby (AI to find the camera and check for any gaps in vision)
        - Building that are near by that will allow Wifi networks access
        - Hotspots in the area (juctions that are likely to have a lot of traffic)
        - fences that could be climbed (AI to find the fence and check for any gaps)
        '''
        for location in self.knownLocations:
            location.runVulnerabilityScan()
            pass


    # SETUP: if you dont have your own google map API key you can find out how to get one here https://arc.net/e/2C6BA2AB-400E-4544-9C56-0653DABC446E
    def setUpGoogleMapsAPI(self):
        self.googleMapsAPIKey = args.gauth_api_key
        # Check if the google maps api key is set
        if self.googleMapsAPIKey == None:
            #  get the GOOGLE_MAP_API_KEY from the environment variables
            self.googleMapsAPIKey =  config('GOOGLE_MAP_API_KEY')
            # os.environ.get('GOOGLE_MAP_API_KEY')
            if self.googleMapsAPIKey == None:
                self.logger.vprint(logTypes.ERROR, 'No google maps api key was specified, please specify one using the --gauth-api-key flag')
                exit(1)

        # Check if the google maps api key is valid
        try:
            # Set up the google maps client
            self.googleMapsClient = googlemaps.Client(key=self.googleMapsAPIKey)
            self.logger.vprint(logTypes.SUCCESS, 'Google maps api key is valid')
        except:
            self.logger.vprint(logTypes.ERROR, 'Google maps api key is invalid')
            exit(1)
        return True


    # generate a report
    def generateReport(self):
        self.logger.vprint(logTypes.SUCCESS, 'Starting report generation')
        # Scan ID
        print(f'\nScan ID: {self.scanID} \n')
        print(f'Known Locations:\n')
        # Locations found
        for i, location in enumerate(self.knownLocations):
            print(f'\tLocation {i}: {location.address["address"]}\n')
            print(f'\t\tGeocode: {location.address["geocode"]["location"]}\n')
            print(f'\tLocation Satellite Image: {location.address["topDownImagePath"]}\n')
            
            print(f'\tNearby Places Within 100m for network Sniffing: \n')
            for place in location.nearBy:
                print(f'\t\tPlace: {place["name"]}\n')
                print(f'\t\t\tGeocode: {place["geometry"]["location"]}\n')
            
            print(f'\tLocation Map for processing Interaction: {location.address["topDownImagePathProcess"]}\n')
            if self.vulnScan:
                print(f'\tLocation Security Detected / Vulnerabilities: \n')
                print(f'\t\tCameras: {location.securityDetected["cameras"]}\n')
                print(f'\t\tFences: {location.securityDetected["fences"]}\n')

            print(f'\n\t###\n')

        
    




if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                    prog = 'Open Source Loacation Fingerprinting',
                    description = "Takes in a site and finds all of the mentioned physical locations - These locations will then be analysed for any security systems in place or barrier etc",
                    epilog = 'CMP320 - Ethical Hacking - 2001890' )

    parser.add_argument('-a',  '--address', action="extend", nargs="+",help='Specify an address/location to analyse, eg: --address "Bell St, Dundee DD11HG"', type=ascii)
    parser.add_argument('-u', '--url', action="extend", nargs="+", help='Specify a url to analyse. Include protocal http(s)://, eg: --url "http://www.abertay.com"', type=ascii)
    parser.add_argument('-d', '--depth', help='Specify the depth of the search (inclusive), eg: --depth 3', type=int, default=1)
    parser.add_argument('-sl', '--scanlimit', help='Specify the number of images to perfrom the AI detection on"', type=int, default=10)
    parser.add_argument('-pl', '--placeslimit', help='Specify the number of places to find within 100m of the location"', type=int, default=5)
    parser.add_argument('-c', '--confidence', help='Specify the AI detection confidence percentage (eg 0.3 = 30%) ', type=float, default=0.6)
    parser.add_argument('--no-relm', help='If the nested urls to scan are allowed to be outbound of the root domain', action='store_false')
    parser.add_argument('--no-vuln', help='If the script should not run physical security scan', action='store_false')
    parser.add_argument('-gak', '--gauth-api-key', help='Add you google maps auth key. or use .env file for GOOGLE_MAP_API_KEY', type=ascii)
    parser.add_argument('-v',  '--verbose', help='Verbose output', action='store_true')

    args = parser.parse_args()
    print(args)
    print(f'{LOGO_OSLFP: ^80}')
    OSLFP = OpenSourceLocationFingerPrint()

