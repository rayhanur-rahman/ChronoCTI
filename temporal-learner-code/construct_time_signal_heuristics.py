from typing import List
import jsonlines
import json
import pandas as pd
from sentence_transformers import SentenceTransformer
from collections import OrderedDict
import tqdm
import torch
from torch import nn
import torch.nn.functional as F
from skorch import NeuralNetClassifier
from sklearn.metrics import classification_report
from skmultilearn.problem_transform import BinaryRelevance
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from skllm.config import SKLLMConfig
from skllm.preprocessing import GPTVectorizer

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques: List = json.load(file)
selectedTechniques.sort(key=lambda v: v['id'])

heuristics_next = ['after', 'afterwards', 'following', 'immediately', 'instantly', 'later', 'next', 'then', 'succeeding', 'subsequent', 'subsequently']
heuristics_previous = ['before', 'previous', 'prior', 'previously', 'preceding']
heuristics_overlap = ['during', 'while', 'within', 'through', 'throughout']
heuristics_concurrent = ['concurrent', 'concurrently', 'contemporary', 'simultaneous', 'simultaneously']

ttp_pairs = []

for idx1 in range(len(selectedTechniques)):
    for idx2 in range(len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))

PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2
PATH_TO_TIME_SIGNAL_HEURISTICS_FEATURE = 'unseen_reports_features/unseen_reports_time_signal_heuristics_features_95.json' # Features_v2/heuristics_time_signals_{prediction_threshold}_v2.json

dataset_report_ttps = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))
reports = list(set([x['report'] for x in dataset_report_ttps]))

all_feature_sets_all_thresholds = []

for prediction_threshold in range(95, 100, 5):
    print('prediction threshold = ', prediction_threshold)
    all_feature_sets = {}
    all_feature_sets['prediction_probability_threshold'] = prediction_threshold
    all_feature_sets['features'] = []
    
    # for rep in reports:
    for idx in tqdm.tqdm(range(len(reports))):
        rep = reports[idx]
        report_sentences = [x for x in dataset_report_ttps if x['report'] == rep ]
                
        feature_set = {}
        feature_set['report-id'] = rep
        feature_set['pair-wise'] = []
        
        ttp_probs = {}
        for te in selectedTechniques:
            te_probs = []    
            for s in report_sentences:
                for ttp in s['ttps']:
                    if te['id'] == ttp['id']:
                        te_probs.append(ttp['prob'])
            te_probs.sort(reverse=True)
            ttp_probs[f'{te["id"]}'] = te_probs[0]
        

        for idx in range(len(ttp_pairs)):
            pair = ttp_pairs[idx]
            te1 = pair[0]
            te2 = pair[1]
            
            features = {}
            features['T1'] = te1['id']
            features['T2'] = te2['id']
            
            next_sentence_pairs = []

            if ttp_probs[f"{te1['id']}"] >= prediction_threshold and ttp_probs[f"{te2['id']}"] >= prediction_threshold:            
                for sent_idx in range(len(report_sentences)):
                    if sent_idx + 1 < len(report_sentences):
                        next_sentence_pairs.append( (sent_idx, sent_idx + 1) )
                                    
                countNext = 0 
                countOverlap = 0
                countConcurrent = 0
                
                pairs = next_sentence_pairs
                for pair in pairs:
                    pred_te1 = [x['prob'] for x in report_sentences[pair[0]]['ttps'] if x['id'] == te1['id']][0]
                    pred_te2 = [x['prob'] for x in report_sentences[pair[1]]['ttps'] if x['id'] == te2['id']][0]
                    
                    s2 = report_sentences[pair[1]]['text']
                    s2 = str(s2).split(' ')
                    
                    if pred_te1 >= prediction_threshold and pred_te2 >= prediction_threshold:
                        for word in heuristics_next:
                            if word in s2:
                                countNext += 1
                        
                        for word in heuristics_overlap:
                            if word in s2:
                                countOverlap += 1
                        
                        for word in heuristics_concurrent:
                            if word in s2:
                                countConcurrent += 1

                features[f'heuristic_next'] = countNext
                features[f'heuristic_overlap'] = countOverlap
                features[f'heuristic_concurrent'] = countConcurrent
            else:          
                features[f'heuristic_next'] = 0
                features[f'heuristic_overlap'] = 0
                features[f'heuristic_concurrent'] = 0
            
            feature_set['pair-wise'].append(features)
            
        
        all_feature_sets['features'].append(feature_set)
    all_feature_sets_all_thresholds.append(all_feature_sets)
            
    json.dump( all_feature_sets, open( f'{PATH_TO_TIME_SIGNAL_HEURISTICS_FEATURE}', 'w' ) )
# json.dump( all_feature_sets_all_thresholds, open( f'json_outputs/consecutive_sentence.json', 'w' ) )