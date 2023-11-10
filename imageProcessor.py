import os
import cv2
import numpy as np
from bs4 import BeautifulSoup # For parsing the html
import subprocess
import requests

# Custom imports
from logger import Logger, logTypes


class ImageVulnProcessor():
    logger = None
    path = ""
    geocode = None
    address = ""
    securityDetected = {
        "cameras": {
            "total": 0,
            "locations":[] # List of tuples containing the lat and long of the camera
        },
        "fences": {
            "total": 0,
            "locations":[] # List of tuples containing the lat and long of the feces
        }
    }
    imagesPath = "/areaImages"
    detectPath = "/detect/oslfp"
    aiMetaData = None # The meta data for the ai vuln scan tuple[scanlimit, min-confidence]
    yoloWeights = "./yolov5/runs/train/exp6/weights/best.pt"
    yoloConfig = "./yolov5x.cfg"
    def __init__(self, path: str, geocode, address: str, logger: Logger, aiMetaData):
        self.logger = logger
        self.path = path
        lat, lng = geocode.values()
        self.geocode =(lat, lng)
        self.address = address
        self.aiMetaData = aiMetaData
        self.getImageofLocation(self.geocode[0], self.geocode[1])
        self.processImage()

    def getImageofLocation(self, lat: float, long: float):
        # Get the image of the location from google maps and save it to the path specified
        # due to the nature of the project, you may need permission from the target for the image processing

        # Check if the folder image already exists if not create it
        workingPath = f"{self.path}{self.imagesPath}"
        if not os.path.exists(workingPath):
            os.makedirs(workingPath)
            self.logger.vprint(logTypes.DEBUG, f'Created folder: {workingPath}')

        # fetch with request images from google maps at geocode and place it in the created folder
        if self.aiMetaData[0] == 0:
            self.logger.vprint(logTypes.WARNING, f'ImageVulnProcessor: Scan limit is 0, skipping image processing')
            return
        else:
            self.logger.vprint(logTypes.INFO, f'ImageVulnProcessor: Scan limit is {self.aiMetaData[0]}')
            self.logger.vprint(logTypes.INFO, f'ImageVulnProcessor: Min confidence is {self.aiMetaData[1]}')
            self.logger.vprint(logTypes.INFO, f'ImageVulnProcessor: Fetching image from google maps')
            # Fetch the image from google maps with google dorking - f"https://www.google.com/search?q=near:+{self.address}"
            url = f"https://www.google.com/search?q=near:+{self.address}&tbm=isch&sa=X&ved=2ahUKEwjOud2b3Jz_AhXMS0EAHTzyAK8Q0pQJegQIShAB&biw=832&bih=855" # May need to change the url session
            search = requests.get(url)
            soup = BeautifulSoup(search.text, 'html.parser')
            soupimages = soup.find_all('img')
            for i, img in enumerate(soupimages):
                if i > self.aiMetaData[0]: break
                img_url = img['src']
                try:
                    self.logger.vprint(logTypes.INFO, f'ImageVulnProcessor: Fetching image: {img_url}')
                    img_data = requests.get(img_url).content
                    with open(f'{workingPath}/{i}.jpeg', 'wb') as handler:
                        handler.write(img_data)
                    
                except:
                    self.logger.vprint(logTypes.WARNING, f'ImageVulnProcessor: Failed to fetch image: {img_url}')
                    continue



    def processImage(self):
        # Process the image and check for any security in place
        # This will be done by using opencv to detect the objects with the YOLO model that we made
        #Reference: https://medium.com/@MrBam44/yolo-object-detection-using-opencv-with-python-b6386c3d6fc1#:~:text=YOLO%20algorithm%20employs%20convolutional%20neural,in%20a%20single%20algorithm%20run.
        # net = cv2.dnn.readNetFromDarknet(self.yoloConfig, self.yoloWeights) # readNetFromDarknet(self.yoloConfig, ) # Not working cause no .cfg file generataed
        classes = ["gate", "camera"]

        # layer_names = net.getLayerNames()
        # output_layers = [layer_names[i[0] - 1] for i in net.getUnconnectedOutLayers()]
        # colours = np.random.uniform(0, 255, size=(len(classes), 3))

        # get the images from the folder
        imagePathScan = f"{self.path}{self.imagesPath}"
        images = os.listdir(imagePathScan)
        if len(images) == 0:
            self.logger.vprint(logTypes.WARNING, f'No images found in: {self.path + self.imagesPath}')
            return
        
        # get the detcted objects from the images
        self.detectObjects(imagePathScan)

        # get the labels from the detect folder
        labels = os.listdir(f"{self.path}{self.detectPath}/labels")
        if len(labels) == 0:
            self.logger.vprint(logTypes.WARNING, f'No labels found in: {self.path + self.detectPath}')
            return
        
        for label in labels:
            if label.endswith(".txt"):
                self.logger.vprint(logTypes.INFO, f'Processing label: {label}')
                labelPath = f"{self.path}{self.detectPath}/labels/{label}"
                with open(labelPath, "r") as f:
                    lines = f.readlines()
                    for line in lines:
                        line = line.split()
                        if line[0] == "0":
                            self.securityDetected["fences"]["total"] += 1
                            if self.securityDetected["fences"]["locations"].count(f"{imagePathScan}/{label.split('.')[0]}") == 0: # Check if the image is already in the list
                                self.securityDetected["fences"]["locations"].append(f"{imagePathScan}/{label.split('.')[0]}")
                        elif line[0] == "1":
                            self.securityDetected["cameras"]["total"] += 1
                            if self.securityDetected["cameras"]["locations"].count(f"{imagePathScan}/{label.split('.')[0]}") == 0:
                                self.securityDetected["cameras"]["locations"].append(f"{imagePathScan}/{label.split('.')[0]}")
                        else:
                            self.logger.vprint(logTypes.WARNING, f'Invalid label: {label}')
                            continue
        # for file in images:
            # if file.endswith(".png") or file.endswith(".jpeg"):
            #     self.logger.vprint(logTypes.INFO, f'Processing image: {file}')
            #     imagePath = self.path + self.imagesPath + "/" + file
            #     self.detectObjects(imagePath)
                # image = cv2.imread(imagePath)
                # image = cv2.resize(image, None, fx=0.4, fy=0.4)
                # height, width, channels = image.shape

                # # Detecting objects
                # blob = cv2.dnn.blobFromImage(image, 0.00392, (416, 416), (0, 0, 0), True, crop=False)
                # net.setInput(blob)
                # outs = net.forward(output_layers)

                # if (len(out[0]) == 0) and (len(out[1]) == 0):
                #     self.logger.vprint(logTypes.INFO, f'No objects detected in image: {file}')
                #     # delete image 
                #     os.remove(imagePath)
                #     continue
                # # Showing informations on the screen
                # class_ids = []
                # confidences = []
                # boxes = []
                # for out in outs:
                    
                #     for detection in out:
                #         scores = detection[5:]
                #         class_id = np.argmax(scores)
                #         confidence = scores[class_id]
                #         if confidence > self.aiMetaData[1]:
                #             # Object detected
                #             center_x = int(detection[0] * width)
                #             center_y = int(detection[1] * height)
                #             w = int(detection[2] * width)
                #             h = int(detection[3] * height)

                #             # Rectangle coordinates
                #             x = int(center_x - w / 2)
                #             y = int(center_y - h / 2)

                #             boxes.append([x, y, w, h])
                #             confidences.append(float(confidence))
                #             class_ids.append(class_id)
                
                # indexes = cv2.dnn.NMSBoxes(boxes, confidences, self.aiMetaData[1], self.aiMetaData[0])
                # font = cv2.FONT_HERSHEY_PLAIN
                # for i in range(len(boxes)):
                #     if i in indexes:
                #         x, y, w, h = boxes[i]
                #         label = str(classes[class_ids[i]])
                #         color = colours[i]
                #         cv2.rectangle(image, (x, y), (x + w, y + h), color, 2)
                #         cv2.putText(image, label, (x, y + 30), font, 3, color, 3)
                #         if label == "camera":
                #             self.securityDetected["cameras"]["total"] += 1
                #             self.securityDetected["cameras"]["locations"].append(imagePath)
                #         elif label == "gate":
                #             self.securityDetected["fences"]["total"] += 1
                #             self.securityDetected["fences"]["locations"].append(imagePath)
                # cv2.imshow("Image", image)
                # cv2.waitKey(0)
                # cv2.destroyAllWindows()

                # gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                # cv2.imshow("Image", gray)
                # cv2.waitKey(0)
                # cv2.destroyAllWindows()
                # cv2.imwrite(self.path + self.imagesPath + "/" + file, gray)
                # print(file)
        pass

    def detectObjects(self, source: str):
        # run the yolo detect script on the image
        cmd = f"python3 ./yolov5/detect.py --weights {self.yoloWeights} --name oslfp --img 416 --conf-thres {self.aiMetaData[1]} --iou-thres 0.3 --source {source} --project {self.path}/detect --exist-ok --save-txt"
        returned_value = subprocess.call(cmd, shell=True)  # returns the exit code in unix
        if (returned_value == 0): 
            self.logger.vprint(logTypes.SUCCESS, f'Yolo detect script returned: {returned_value}, Success')
        else:
            self.logger.vprint(logTypes.ERROR, f'Yolo detect script returned: {returned_value}, Error')
        


if __name__ == "__main__":
    process = ImageVulnProcessor("./testing",{'lat':56.4631101, "lng":-2.9737651},"Bell St, Dundee DD1 1HG, Uk",  Logger(logTypes.DEBUG), (10, 0.5))
    
    print(process.securityDetected)
        
        