from curses import pair_content
import datetime, json
from tokenize import group
import pandas as pd 
import domain
import tabulate as tb
from typing import Counter, List
import matplotlib.pyplot as plt 
import seaborn as sns
import numpy as np
import networkx as nx 
import domain
import statistics, math
from networkx.algorithms import bipartite as bp
from networkx.algorithms import community as nxcm
import scipy.stats as stats
from sklearn.metrics.pairwise import cosine_similarity
from scipy import spatial
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import apriori, fpmax, fpgrowth
from mlxtend.frequent_patterns import association_rules
from stix2 import MemoryStore, Filter
import os, re
from dateutil.parser import parse
import tabulate as tb
import warnings, numpy as np
from numpy.linalg import norm
warnings.filterwarnings("ignore")
import tqdm



def print_dataframe(df, type = 'psql'):
    print(tb.tabulate( df , headers='keys', tablefmt=f'{type}'))

def cleanProcedureText(text):    
    txt = text
    
    # matchObject = re.search(r"\[([A-Za-z0-9_.@$\- ]+)\]", txt)
    # print(matchObject.group(1))
    
    txt = re.sub(r"\[([A-Za-z0-9_.@$\- ]+)\]", '', txt) # clean group or software name
    # txt = re.sub(r"\(Citation: [a-zA-Z0-9_.@/!\- ]+\)", '', txt) # clean citation remarks
    txt = re.sub(r"\(Citation: [^\)]+\)", '', txt) # clean citation remarks
    txt = re.sub(r"\(https://attack.mitre.org/[a-zA-Z0-9]+/[a-zA-Z0-9]+\)", '', txt) # clean attacl urls
    txt = re.sub(r"<code>", '', txt) # clean <code> verbatims
    txt = re.sub(r"</code>", '', txt) # clean <code> verbatims
    
    txt = txt.lower().strip()
    return txt

def cleanProcedureText2(text):    
    txt = text
    
    matchObject = re.search(r"\[([A-Za-z0-9_.@$\- ]+)\]", txt)
    # print(matchObject.group(1))
    
    if matchObject != None:
        txt = re.sub(r"\[([A-Za-z0-9_.@$\- ]+)\]", matchObject.group(1), txt) # clean group or software name
    # txt = re.sub(r"\(Citation: [a-zA-Z0-9_.@/!\- ]+\)", '', txt) # clean citation remarks
    txt = re.sub(r"\(Citation: [^\)]+\)", '', txt) # clean citation remarks
    txt = re.sub(r"\(https://attack.mitre.org/[a-zA-Z0-9]+/[a-zA-Z0-9]+\)", '', txt) # clean attacl urls
    txt = re.sub(r"<code>", '', txt) # clean <code> verbatims
    txt = re.sub(r"</code>", '', txt) # clean <code> verbatims
    
    txt = txt.lower().strip()
    return txt

def buildContingencyTable(techniqueId1, techniqueId2, techniques, attackCases):
    te1 = [x for x in techniques if x.id == techniqueId1][0]
    te2 = [x for x in techniques if x.id == techniqueId2][0]
    
    # print(f'{len([x for x in reports if te1 in x.techniques])}')
    
    te1AndTe2 = len( [x for x in attackCases if te1.id in x and te2.id in x])
    te1AndNotTe2 = len( [x for x in attackCases if te1.id in x and te2.id not in x])
    notTe1AndTe2 = len( [x for x in attackCases if te1.id not in x and te2.id in x])
    notTe1AndNotTe2 = len( [x for x in attackCases if te1.id not in x and te2.id not in x])
    
    return [te1AndTe2, te1AndNotTe2, notTe1AndTe2, notTe1AndNotTe2]

def dumpContingencyTable(techniques, attackCases):
    file = open('data/contingency.csv', 'w')
    file.write(f'teX,teY,xy,xny,nxy,nxny\n')
    history = []
    idx = 0
    
    for idx1 in tqdm.tqdm(range(len(techniques))):
    # for idx1 in range(0, len(techniques)):
        for idx2 in range(idx + 1, len(techniques)):
            ct = buildContingencyTable(techniques[idx1].id, techniques[idx2].id, techniques, attackCases)
            file.write(f'{techniques[idx1].id},{techniques[idx2].id},{ct[0]},{ct[1]},{ct[2]},{ct[3]}\n')
        # print(idx)
        idx += 1
    file.close()
    return

def getTeName(teId, techniques):
    teName = [x for x in techniques if x.id == teId][0].name
    return teName

def calcSupportX(a, b, c, d, dblen):
    try:
        return (a+b)/dblen
    except:
        return 0

def calcSupportY(a, b, c, d, dblen):
    try:
        return (a+c)/dblen
    except:
        return 0

def calcSupportXY(a, b, c, d, dblen):
    try:
        return a/dblen
    except:
        return 0

def calcConfidence(a, b, c, d):
    try:
        return a/(a+b)
    except:
        return 0

def calcCausalConfidence(a, b, c, d):
    try:
        
        xy = (a+c)/(a+b)
        nxny = (b+d)/(c+d)
        
        return (xy+nxny)*0.5
    except:
        return 0

def calcCausalSupport(a, b, c, d):
    total = a + b + c + d
    try:
        pXandY = a / total
        pNoXandNoY = d / total
        return pXandY + pNoXandNoY
    except:
        return 0

def calcPMI(a, b, c, d, dblen):
    try:
        return math.log2( (a * dblen) / (a+b)*(a+c) ) 
    except:
        return 0

def calcPhi(a, b, c, d, dblen):
    try:
        pxy = a
        px = (a+b)/dblen
        py = (a+c)/dblen
        return (a*d - b*c) / math.sqrt( (a+b)*(c+d)*(a+c)*(b+d) )
    except:
        return 0

def normalize(vector):
    minVal = min(vector)
    maxVal = max(vector)
    return [(x-minVal)/(maxVal-minVal) for x in vector]

def normalizeNetworkXDict(dictionary: dict):
    valueList = [dictionary[k] for k in dictionary.keys()]
    minValue = min(valueList)
    maxValue = max(valueList)
    
    for k in dictionary.keys():
        dictionary[k] = (dictionary[k] + 1 - minValue) / (maxValue + 1 - minValue)
    
    return dictionary

def getFileteredSentence(nlp, text):
    document = nlp(text)
    filteredDocument = []
    listOfAdditionalStopWords = ['`', '>', '+', '|', '=', '^', '~']
    for token in document:
        if (not token.is_stop) and (not token.is_digit) and (not token.is_punct) and (not token.is_space) and (not token.is_currency) and (not token.is_bracket) and (not token.like_email) and (token.pos_ != 'NUM') and (not token.like_url) and (token.text not in listOfAdditionalStopWords):
            filteredDocument.append(token.lemma_.lower())
    return filteredDocument

def getFilteredCorpus(nlp, procedures, reBuild = False, techniqueToGet = 'all'):
    filteredCorpus = []
    listOfAdditionalStopWords = ['`', '>', '+', '|', '=', '^', '~']
    if reBuild:
        idx = 0
        for proc in procedures:
            text = proc.description
            document = nlp(text)
            filteredDocument = []
            for token in document:
                if (not token.is_stop) and (not token.is_digit) and (not token.is_punct) and (not token.is_space) and (not token.is_currency) and (not token.is_bracket) and (not token.like_email) and (token.pos_ != 'NUM') and (not token.like_url) and (token.text not in listOfAdditionalStopWords):
                    filteredDocument.append( (token.lemma_, token.pos_, token.tag_, token.dep_) )
            filteredCorpus.append( (filteredDocument, proc.technique.parentId) )
            print(idx)
            idx += 1

        dumpFileForFilteredCorpus = open('data/filteredCorpus.json', 'w')
        json.dump(filteredCorpus, dumpFileForFilteredCorpus)
    else:
        dumpFileForFilteredCorpus = open('data/filteredCorpus.json', 'r')
        filteredCorpus = json.load(dumpFileForFilteredCorpus)
    
    if techniqueToGet == 'all':
        return [x[0] for x in filteredCorpus]
    else:
        return [x[0] for x in filteredCorpus if x[1] == techniqueToGet]

def getCosine(v1, v2):
    return (np.dot(v1, v2) / (norm(v1) * norm(v2)))

def appendText(row1, row2):
    return row1 + ' ' + row2

def getAssociationRuleMiningModel(datasetInstance, reBuildContingency = False, reBuildDump = False):
    if reBuildContingency:
        tes = [x for x in datasetInstance.techniques if not x.isSubTechnique]
        dumpContingencyTable(tes, datasetInstance.attackInstances)
    ctdf = pd.read_csv('data/contingency.csv')
    
    if reBuildDump:    
        dblen = len(datasetInstance.attackInstances)

        ctdf['teXN'] = ctdf.apply(lambda row : getTeName(row.teX, datasetInstance.techniques), axis = 1)
        ctdf['teYN'] = ctdf.apply(lambda row : getTeName(row.teY, datasetInstance.techniques), axis = 1)
        ctdf['supportX'] = ctdf.apply(lambda row: calcSupportX(row.xy, row.xny, row.nxy, row.nxny, dblen), axis = 1)
        ctdf['supportY'] = ctdf.apply(lambda row: calcSupportY(row.xy, row.xny, row.nxy, row.nxny, dblen), axis = 1)
        ctdf['supportXY'] = ctdf.apply(lambda row: calcSupportXY(row.xy, row.xny, row.nxy, row.nxny, dblen), axis = 1)

        ctdf['pmi'] = ctdf.apply(lambda row: calcPMI(row.xy, row.xny, row.nxy, row.nxny, dblen), axis = 1)
        ctdf['phi'] = ctdf.apply(lambda row: calcPhi(row.xy, row.xny, row.nxy, row.nxny, dblen), axis = 1)
        ctdf['causup'] = ctdf.apply(lambda row: calcCausalSupport(row.xy, row.xny, row.nxy, row.nxny), axis = 1)
        ctdf['jaccard'] = ctdf['supportXY'] / (ctdf['supportX'] + ctdf['supportY'] - ctdf['supportXY'])

        ctdf['confidence'] = ctdf.apply(lambda row: calcConfidence(row.xy, row.xny, row.nxy, row.nxny), axis = 1)
        ctdf['confidenceRev'] = ctdf.apply(lambda row: calcConfidence(row.xy, row.nxy, row.xny, row.nxny), axis = 1)
        
        ctdf['cauconf'] = ctdf.apply(lambda row: calcCausalConfidence(row.xy, row.xny, row.nxy, row.nxny), axis = 1)
        ctdf['cauconfRev'] = ctdf.apply(lambda row: calcCausalConfidence(row.xy, row.nxy, row.xny, row.nxny), axis = 1)
        
        ctdf['av'] = ctdf['confidence'] - ctdf['supportY']
        ctdf['avRev'] = ctdf['confidenceRev'] - ctdf['supportX']
        
        ctdf['conviction'] = (1 - ctdf['supportY']) / (1 - ctdf['confidence'])
        ctdf['convictionRev'] = (1 - ctdf['supportX']) / (1 - ctdf['confidenceRev'])
        
        ctdf.to_csv('data/ctdf.dump.csv', header=True, index=False)
    
    ctdf = pd.read_csv('data/ctdf.dump.csv')
    return ctdf

