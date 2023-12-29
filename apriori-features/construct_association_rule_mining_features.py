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
import domain, utils
import tqdm

def get_df(rule_mining_df, te1Id, te2Id):
    dfq1 = rule_mining_df.query(f' teX == "{te1Id}" and teY == "{te2Id}" ')
    dfq2 = rule_mining_df.query(f' teX == "{te2Id}" and teY == "{te1Id}" ')
    
    if len(dfq1) > len(dfq2): 
        return dfq1
    elif len(dfq1) < len(dfq2): 
        return dfq2
    else: return dfq1
    

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques = json.load(file)
techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

ttp_pairs = []

for idx1 in range(len(selectedTechniques)):
    for idx2 in range(len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))

dataset_instance = domain.Dataset()
techniques = dataset_instance.techniques
procedures = dataset_instance.procedures

rule_mining_df = utils.getAssociationRuleMiningModel(dataset_instance)
rule_mining_df = rule_mining_df.sort_values(by = ['conviction'], ascending=False)

convictionLs = rule_mining_df['conviction'].tolist()

print(len(rule_mining_df))

columns = list(rule_mining_df.columns)

for item in ['teX', 'teY', 'teXN', 'teYN']:
    columns.remove(item)

PATH_TO_CTI_REPORTS_FOLDER = 'unseen_reports' # reports
PATH_TO_RULE_MINING_FEATURES = 'unseen_reports_rule_mining_features.json' # rule_mining_features.json

file_names = os.listdir(f'{PATH_TO_CTI_REPORTS_FOLDER}')

all_feature_sets = []

static_feature = []
for idx in range(len(ttp_pairs)):
        pair = ttp_pairs[idx]
        te1 = pair[0]
        te2 = pair[1]
        
        te1Id = te1['id']
        te2Id = te2['id']

        dfq = get_df(rule_mining_df, te1Id, te2Id)
        
        features = {}
        features['T1'] = te1['id']
        features['T2'] = te2['id']
        
        if len(dfq) > 0:
            for col in columns:
                features[col] = [row[col] for idx, row in dfq.iterrows()][0]
        else:
            for col in columns:
                features[col] = 0
        
        static_feature.append(features)

for count in tqdm.tqdm(range(len(file_names))):
    file_name = file_names[count]

# for idx in tqdm.tqdm(range(len(file_names))):
    # print(file_name)
    # file_name = file_names[idx]
    # print(file_name)
    
    feature_set = {}
    
    if '.md' in file_name:
        feature_set['report'] = file_name[:-3]
    
    if '.txt' in file_name:
        feature_set['report'] = file_name[:-4]
    
    feature_set['pair-wise'] = static_feature
    
    # feature_set['pair-wise'] = []
    
    # for idx in range(len(ttp_pairs)):
    #     pair = ttp_pairs[idx]
    #     te1 = pair[0]
    #     te2 = pair[1]
        
    #     te1Id = te1['id']
    #     te2Id = te2['id']

    #     dfq = get_df(rule_mining_df, te1Id, te2Id)
        
    #     features = {}
    #     features['T1'] = te1['id']
    #     features['T2'] = te2['id']
        
    #     if len(dfq) > 0:
    #         for col in columns:
    #             features[col] = [row[col] for idx, row in dfq.iterrows()][0]
    #     else:
    #         for col in columns:
    #             features[col] = 0
        
    #     feature_set['pair-wise'].append(features)
    
    all_feature_sets.append(feature_set)

json.dump( all_feature_sets, open( f'{PATH_TO_RULE_MINING_FEATURES}', 'w' ) )
    
    
        
        
        
        
        
        



