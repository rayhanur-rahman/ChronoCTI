import json
import pandas as pd
import os
import random
import spacy
import spacy_transformers
import json, statistics, tqdm
import subprocess, sys
from numpy.linalg import norm
import numpy as np

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
        
model = spacy.load('cti_w2v_v2')

PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2
PATH_TO_SENTENCE_SIMILARITY_FEATURE = 'unseen_reports_features/unseen_reports_sentence_similarity_features_95.json' # Features_v2/sentence_similarity_feature_threshold_95_v2.json


dataset_report_ttps = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))
reports = list(set([x['report'] for x in dataset_report_ttps]))

all_feature_sets_all_thresholds = []


for prediction_threshold in range(95, 100, 5):
    print('prediction threshold = ', prediction_threshold)
    all_feature_sets = {}
    all_feature_sets['prediction_probability_threshold'] = prediction_threshold
    all_feature_sets['features'] = []
    
    for idx in tqdm.tqdm(range(len(reports))):
        rep = reports[idx]
        report_sentences = [x for x in dataset_report_ttps if x['report'] == rep ]
        docs = [model(x['text']).vector for x in report_sentences]
                
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
            
            if ttp_probs[f"{te1['id']}"] >= prediction_threshold and ttp_probs[f"{te2['id']}"] >= prediction_threshold:
            
                sentences_having_te1 = []
                sentences_having_te2 = []
                
                for sent in report_sentences:
                    pred_te1 = [x['prob'] for x in sent['ttps'] if x['id'] == te1['id']][0]
                    pred_te2 = [x['prob'] for x in sent['ttps'] if x['id'] == te2['id']][0]
                    
                    if pred_te1 >= prediction_threshold:
                        sentences_having_te1.append(sent['line'])
                    
                    if pred_te2 >= prediction_threshold:
                        sentences_having_te2.append(sent['line'])
            
            
                if len(sentences_having_te1) * len(sentences_having_te2) > 0:
                    try:
                        vec1 = docs[sentences_having_te1[0]]
                        vec2 = docs[sentences_having_te2[0]]
                        
                        for s in sentences_having_te1[1:]:
                            vec1 += docs[s]
                        
                        for s in sentences_having_te2[1:]:
                            vec2 += docs[s]
                        
                        vec1 = vec1 / len(sentences_having_te1)
                        vec2 = vec2 / len(sentences_having_te2)

                        if (norm(vec1)*norm(vec2)) != 0:
                            features[f'similarity'] = float(np.dot(vec1, vec2)/(norm(vec1)*norm(vec2)))
                        else:
                            features[f'similarity'] = 0
                    except:
                        features[f'similarity'] = 0
                    
                else:
                    features[f'similarity'] = 0
            
            else:
                features[f'similarity'] = 0
            
            feature_set['pair-wise'].append(features)
            
        
        all_feature_sets['features'].append(feature_set)
    all_feature_sets_all_thresholds.append(all_feature_sets)
            
    json.dump( all_feature_sets, open( f'{PATH_TO_SENTENCE_SIMILARITY_FEATURE}', 'w' ) )
# json.dump( all_feature_sets_all_thresholds, open( f'json_outputs/consecutive_sentence.json', 'w' ) )