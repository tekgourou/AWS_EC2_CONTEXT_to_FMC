#!/bin/env python

'''
PURPOSE:
THIS SCRIPT IMPORTS ALL THE OPERATING SYSTEMS INFORMATION FROM AWS EC2 API,
    PRINTS THE OUTPUT TO A CSV AND THEN IMPORTS THE CSV INTO FIREPOWER MANAGEMENT CENTER USING THE HOST INPUT API OF FMC.

DEPENDENCIES / REQUIREMENTS:
1- PYTHON 3.6
2- PERL 5
3- ACCOUNT ON AWS CLOUD AN API KEY GENERATED.
4- FIREPOWER MANAGEMENT CENTER (FMC) 6.x +
5- 'requests' MODULE, THAT CAN BE INSTALLED BY EXECUTING THE COMMAND "python -m pip install requests"
5- 'boto3' MODULE, THAT CAN BE INSTALLED BY EXECUTING THE COMMAND "python -m pip install boto3"
6- UPDATE THE 'parameters.json' FILE WITH THE DETAILS BEFORE EXECUTING THIS SCRIPT
7- TCP PORT 443 TO DUO API CLOUD.
8- TCP PORT 8307 TO FMC
9- FMC HOST INPUT API CLIENT CERTIFICATE FILE (xxxxxx.pkcs12) GENERATED FROM FMC, DOWNLOADED IN THIS SCRIPT'S LOCAL DIRECTORY.
     TO GENERATE THE CERTIFICATE, LOGIN TO FMC WEB GUI AND NAVIGATE TO SYSTEM -> INTEGRATIONS -> HOST INPUT CLIENT -> CREATE CLIENT
     -> HOSTNAME IS THE IP OF THE HOST RUNNING THIS SCRIPT AND ***NO PASSWORD*** -> DOWNLOAD THE PKCS12 FILE IN THIS SCRIPT'S LOCAL DIRECTORY

This script is based on the AMP4Endpoint Host Input for FMC. Modified by Alexandre Argeris (aargeris@cisco.com)

NOTE:
All Cisco software is subject to the Supplemental End User License Agreements (SEULA) located at https://www.cisco.com/c/en/us/about/legal/cloud-and-software/software-terms.html
'''

import json
import sys
import subprocess
import logging
import os
from AWS_EC2_instance_info import get_aws_ec2_info

print('##########################################################')
print('#       AWS EC2 instance context sharing to FMC          #')
print('#            Production use at your own risk             #')
print('#       aargeris@cisco.com, alexandre@argeris.net        #')
print('#        Run this script once to detect any error        #')
print('#             then put it in your crontab                #')
print('##########################################################')
print()

auditlogfile = "AUDIT.log"

# Start Log File Handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(auditlogfile)
datefmt = '[%Y-%m-%d %H:%M:%S]'
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Import variables to get configuration
logger.info("###############################################################################")
logger.info("Starting execution of the script")
config = ''
try:
    config = json.loads(open("parameters.json").read())
    logger.info("Found the parameters file - 'parameters.json'. Loading in parameters now....")
except Exception as err:
    logger.error(
        "ERROR in reading the 'parameters.json' file or the file does not exist. So exiting!  Below is the exact exception message.")
    print(
        "ERROR in reading the 'parameters.json' file or the file does not exist. So exiting!  Below is the exact exception message.")
    logger.error(str(err))
    print(str(err))
    logger.error("Check out the sample 'parameters.json' file for example....")
    print("Check out the sample 'parameters.json' file for example....")
    sys.exit()

csv = open("./hostinputcsv.txt", "w")

# Create dictionary of variables
var = {
    "FMC_ipaddress": config["FMC_ipaddress"],
    "FMC_host_vuln_db_overwrite_OR_update": config["FMC_host_vuln_db_overwrite_OR_update"],
    "push_changes_to_fmc": config["push_changes_to_fmc"],
    "FMC_user": config["FMC_user"],
    "FMC_password": config["FMC_password"],
}

# Check to make sure there is data in the parameters
for key in var.keys():
    value = var[key]
    if value == "":
        logger.error("Missing Value for the Parameter {}.... So exiting!".format(key, value))
        print("Missing Value for the Parameter {}.... So exiting!".format(key, value))
        sys.exit()

if 'FMC_ipaddress' not in var.keys():
    logger.error(
        "Missing the Parameter - 'FMC_ipaddress'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'FMC_ipaddress'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if 'FMC_host_vuln_db_overwrite_OR_update' not in var.keys():
    logger.error(
        "Missing the Parameter - 'FMC_host_vuln_db_overwrite_OR_update'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'FMC_host_vuln_db_overwrite_OR_update'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if var['FMC_host_vuln_db_overwrite_OR_update'] != "overwrite" and var[
    'FMC_host_vuln_db_overwrite_OR_update'] != "update":
    logger.error(
        "Parameter - 'FMC_host_vuln_db_overwrite_OR_update' can be either set to \"update\" or \"overwrite\". Any other value is not allowed... So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Parameter - 'FMC_host_vuln_db_overwrite_OR_update' can be either set to \"update\" or \"overwrite\". Any other value is not allowed... So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()
if 'push_changes_to_fmc' not in var.keys():
    logger.error(
        "Missing the Parameter - 'push_changes_to_fmc'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    print(
        "Missing the Parameter - 'push_changes_to_fmc'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
    sys.exit()

logger.info("Parameter check complete")

#Prepare the CSV for FMC host input
csv.write("SetSource,AWS EC2 API\n")
csv.write("AddHostAttribute,{},{}\n".format('AWS EC2 Info', 'text'))

def add_host_to_csv(ip, opersys, AWS_EC2_INFO ):
    csv.write("AddHost,{}\n".format(ip))
    csv.write("SetAttributeValue,{},{},{}\n".format(ip, 'AWS EC2 Info', AWS_EC2_INFO))
    if "Windows" in opersys:
        csv.write("SetOS,{},Microsoft,Windows,\"{}\"\n".format(ip, opersys))
    elif "Amazon" in opersys:
        csv.write("SetOS,{},Amazon,Linux,\"{}\"\n".format(ip, opersys))
    elif "Ubuntu" in opersys:
        csv.write("SetOS,{},Ubuntu,Linux,\"{}\"\n".format(ip, opersys))
    elif "SUSE" in opersys:
        csv.write("SetOS,{},Suse,Linux,\"{}\"\n".format(ip, opersys))
    elif "Red Hat" in opersys:
        csv.write("SetOS,{},Red Hat,Linux,\"{}\"\n".format(ip, opersys))
    elif "CentOS" in opersys:
        csv.write("SetOS,{},CentOS,Linux,\"{}\"\n".format(ip, opersys))
    else:
        csv.write("SetOS,{},{},{},\"{}\"\n".format(ip, opersys, "TBD", "TBD"))

# ADDING ENDPOINT CONTEXT to CSV
instance_list = get_aws_ec2_info()
for instance in instance_list:
    if instance['Public IP'] == None:
        AWS_EC2_INFO = ('EC2 Name: {} - EC2 Type: {} - EC2 VPC ID: {}'.format(instance['Name'], instance['Type'], instance['VPC ID']))
        add_host_to_csv(instance['Private IP'], instance['Image Description'], AWS_EC2_INFO)
    else:
        AWS_EC2_INFO = ('EC2 Name: {} - Public IP: {} - EC2 Type: {} - EC2 VPC ID: {}'.format(instance['Name'], instance['Public IP'],instance['Type'], instance['VPC ID']))
        add_host_to_csv(instance['Private IP'], instance['Image Description'], AWS_EC2_INFO)
        AWS_EC2_INFO = ('EC2 Name: {} - Private IP: {} - EC2 Type: {} - EC2 VPC ID: {}'.format(instance['Name'], instance['Private IP'], instance['Type'], instance['VPC ID']))
        add_host_to_csv(instance['Public IP'], instance['Image Description'], AWS_EC2_INFO)

#SENDING CSV File to FMC via HOST INPUT API
if var['FMC_host_vuln_db_overwrite_OR_update'] == "overwrite":
    csv.write("ScanFlush")
else:
    csv.write("ScanUpdate")

csv.close()
logger.info("Completed the Parsing of the events and wrote the information to the CSV file")

if not var["push_changes_to_fmc"]:
    logger.info("Not supposed to push any changes to FMC as per the parameters in 'parameters.json'...  So exiting!")
    print("Not supposed to push any changes to FMC as per the parameters in 'parameters.json'...  So exiting!")
    sys.exit()
else:
    # Call the Perl Host Input SDK client for the Host Input
    logger.info("Calling the PERL client of FMC Host Input SDK to push the CSV details into FMC")

    perl_log_filename = ".HostInput.log"
    if os.path.exists(perl_log_filename):
        try:
            os.remove(perl_log_filename)
        except:
            pass

    logger.info("COMMAND:-" + " perl" + " sf_host_input_agent.pl" + " -server={}".format(
        var["FMC_ipaddress"]) + " -level=3" + " -logfile={}".format(
        perl_log_filename) + " -plugininfo=hostinputcsv.txt" + " csv" + " -runondc=n")

    pipe = subprocess.call(["perl", "sf_host_input_agent.pl", "-server={}".format(var["FMC_ipaddress"]), "-level=3",
                            "-logfile={}".format(perl_log_filename), "-plugininfo=hostinputcsv.txt", "csv",
                            "-runondc=n"])

    logger.info("The output of the script is saved in a seperate file. Copying the content of that file here as-it-is")

    try:
        with open(perl_log_filename) as f:
            output = f.read()
            logger.info("\n" + output)
            f.close()
        os.remove(perl_log_filename)
    except:
        logger.error(
            "Could not open the " + perl_log_filename + " file, so probably the PERL script execution might have failed")
        print(
            "Could not open the " + perl_log_filename + " file, so probably the PERL script execution might have failed")
        sys.exit()

print("The output of the script is appended to '" + auditlogfile + "' file")
