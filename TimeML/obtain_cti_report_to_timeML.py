from fileinput import filename
import re
import subprocess
import os
from bs4 import BeautifulSoup
import spacy, benepar
import ParseTree
from bs4 import BeautifulSoup
from tqdm import tqdm

### This program take a CTI report input and outputs TimeML xml file for each CTI report

PATH_TO_CTI_REPORTS = 'unseen_reports'
PATH_TO_TIMEML_OUTPUT = 'unseen_reports_timeML_outputs'

list_of_cti_report_file_names = []
list_of_cti_report_file_names.extend( os.listdir(PATH_TO_CTI_REPORTS) )

for idx in tqdm(range(len(list_of_cti_report_file_names))):
    file_name = list_of_cti_report_file_names[idx]
    existing_files = os.listdir(PATH_TO_TIMEML_OUTPUT)
    if f'{file_name[:-3]}.xml' not in existing_files:
        command_text = f'python tarsqi.py {PATH_TO_CTI_REPORTS}/{file_name} {PATH_TO_TIMEML_OUTPUT}/{file_name[:-3]}.xml'
        # print(file_name)
        # print(command_text)
        os.system(command_text)
        # input('*** Press to continue ***')

