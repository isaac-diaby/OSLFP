# Imports 
import os
import googlemaps
import folium

# Custom imports
from imageProcessor import ImageVulnProcessor
from logger import Logger, logTypes


class AddressHandler():
    gmaps = None
    logger = None
    address = None
    imageBuildingProcessor = None
    scanID = None
    aiMetaData = None # The meta data for the ai vuln scan tuple[scanlimit, min-confidence]
    nearBy = []
    maxPlaces = 5 # Only get the first 5 results
    securityDetected = None
    workingDirectory = None # The directory that the working with. This is used to create the scan folder
    def __init__(self, address: str, googleMapsClient, logger: Logger, aiMetaData, nearbyPlacesLimit: int, scanid: str):
        self.gmaps = googleMapsClient
        self.logger = logger
        self.scanID = scanid
        self.aiMetaData = aiMetaData
        self.maxPlaces = nearbyPlacesLimit
        self.workingDirectory = f'./scans/{self.scanID}'
        self.address = {
            'address': address,
            'id': "",
            'geocode': {
                'geometry': {'bounds': {
                    'northeast': {'lat':None, 'lng': None},
                    'southwest': {'lat': None, 'lng': None}
                    },
                'location': {'lat': None, 'lng': None},
                'viewport': {
                    'northeast': {'lat': None, 'lng': None},
                    'southwest': {'lat': None, 'lng': None}
                    }
                }
            },
            'types': None,
            'topDownImagePath': None,
            'topDownImagePathProcess': None
        }

        try:
            self.findLocationGeoCodeFromAddress()
            self.getTopDownImageOfLocation()
            self.findNearbyBuildings()
            self.getTopDownImageOfLocationForProcessing()
            
        except Exception as e:
            self.logger.vprint(logTypes.ERROR, f'AddressHandler failed to initialise with address: {self.address}')
            self.logger.vprint(logTypes.ERROR, f'Error: {e}')
            raise e
        




    def findLocationGeoCodeFromAddress(self):
#       Find the geocode from the address
        geocodeInfoFromGoogleMaps = self.gmaps.geocode(self.address["address"])[0]
#       [
#       'formatted_address': 'Bell St, Dundee DD1 1HG, UK',
#       'geometry': {'bounds': {
#           'northeast': {'lat': 56.46340780000003, 'lng': -2.972609899999999},
#           'southwest': {'lat': 56.46278379999998, 'lng': -2.974908200000001}
#           },
#       'location': {'lat': 56.4631101, 'lng': -2.9737651},
#       'viewport': {
#           'northeast': {'lat': 56.46444478029151, 'lng': -2.972410069708498},
#           'southwest': {'lat': 56.46174681970851, 'lng': -2.975108030291502}
#       }},
#       'place_id': 'EhtCZWxsIFN0LCBEdW5kZWUgREQxIDFIRywgVUsiLiosChQKEgkN3WThwVyGSBEWgLkJCfTHLBIUChIJI584lcFchkgRlitq0FAV4Ro',
#       'types': ['route']}
#       ]

        self.address["address"] = geocodeInfoFromGoogleMaps["formatted_address"]
        self.address["types"] = geocodeInfoFromGoogleMaps["types"]
        self.address["id"] = geocodeInfoFromGoogleMaps["place_id"]
        self.address["geocode"] = geocodeInfoFromGoogleMaps["geometry"]
        self.logger.vprint(logTypes.SUCCESS, f'AddressHandler initialised with address: {self.address["address"]}')
        

#   Get the top down image of the location
    def getTopDownImageOfLocation(self):
        images_folder = f"{self.workingDirectory}/{self.address['id']}"
        self.address["topDownImagePath"] = f"{images_folder}/original.png"
        lat, lng = self.address["geocode"]['location'].values()

#       Check if the folder image already exists if not create it
        if not os.path.exists(images_folder):
            os.makedirs(images_folder)
            self.logger.vprint(logTypes.DEBUG, f'Created folder: {images_folder}')

#       Download the image
        with open(self.address["topDownImagePath"], 'wb') as out:
            for chunk in self.gmaps.static_map(size=(500, 500),
                                        center=(lat,lng),
                                        zoom=17,
                                        maptype='satellite'):
                if chunk:
                    out.write(chunk)
        self.logger.vprint(logTypes.DEBUG, f'Saving satellite image to: {self.address["topDownImagePath"]}')

    def getTopDownImageOfLocationForProcessing(self):
        images_folder = f"{self.workingDirectory}/{self.address['id']}"
        self.address["topDownImagePathProcess"] = f"{images_folder}/process.html"
        lat, lng = self.address["geocode"]['location'].values()
        m = folium.Map(location=[lat, lng], zoom_start=18) # create the interactive map 

        # Add the marker for the nearby places
        for place in self.nearBy:
            folium.Marker([place['geometry']['location']['lat'], place['geometry']['location']['lng']], popup=place['name']).add_to(m)

        self.logger.vprint(logTypes.INFO, f'Saving map to: {self.address["topDownImagePathProcess"]}')
        m.save(self.address["topDownImagePathProcess"])
    
    # Near by public buildings that are with in 100m (WIFI connection) - so that a hacker will still be within range to attempt an attack
    def findNearbyBuildings(self):
        lat, lng = self.address["geocode"]['location'].values()
       
        for place in self.gmaps.places_nearby(location=(lat,lng), radius=100)['results']: 
            if self.maxPlaces > 0:
                if "locality" in place['types']:
                    continue
                placeInfo = {
                    'name': place['name'],
                    'place_id': place['place_id'],
                    'types': place['types'],
                    'geometry': place['geometry'],
                    'vicinity': place['vicinity']
                }
                self.logger.vprint(logTypes.INFO, f'Found nearby place: {placeInfo["name"]}')
                self.nearBy.append(placeInfo)
                self.maxPlaces -= 1
            else:
                break
        self.logger.vprint(logTypes.DEBUG, f'Found {len(self.nearBy)} nearby places')
            
        
    #  Run the vulnerability scan on the images found in the area for cameras and feces
    def runVulnerabilityScan(self):
        vulnerabilityScan = ImageVulnProcessor(f"{self.workingDirectory}/{self.address['id']}", self.address["geocode"]['location'], self.address["address"], self.logger, aiMetaData=self.aiMetaData)
        self.securityDetected = vulnerabilityScan.securityDetected
        pass


if __name__ == '__main__':
    addressHandler = AddressHandler()