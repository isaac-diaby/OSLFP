# CMP320 Scripting Project - Location Based Web Scraping With Physical Security Automation

## Description 

The over all aim for this script to to be able to provide the script with a website that will be scraped for any address relating to the business. The script will then get a 3d rendering of the and be able to analyse the physical security of the building / offices. 

read the CMP320_Scripting_Project.docx write up for more information on the design and implementation of the project.

### The Features that I will possibly implement are 

- Identifies Walls / fences around the building 
- Near by public buildings that are with in 100m (WIFI connection) - so that a hacker will still be within range to attempt an attack
- Congestion in the road/pathing - These are point that most employee are likely to walk / drive through


Note: This will be part of OSINT fingerprinting as ill only be able to work with information that's already in the public domain. if the area is off limit no data or information will be scraped. 

## How to use 

### Help
```bash 
python main.py -h
```
outputs the help command for the project 

### Set a url as the entry point
```bash 
python main.py -u "http://www.abertay.ac.uk" -v
```
This will set the provided url or urls as the entry point of the addresses (loaction) scans

### (Optional) add a known address 
```bash 
python main.py -a "Abertay University Bell Street, Dundee DD1 1HG UK" -v
```

After running the command you will be able to see a HTML website that displays the gathered info and findings

## Author

Moustapha Isaac Diaby | 2001890 | 13/03/23