import json
import pandas as pd
import os
import random
import spacy
import spacy_transformers
import json, statistics, tqdm

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques = json.load(file)

techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

ttp_pairs = []

for idx1 in range(len(selectedTechniques)):
    for idx2 in range(idx1 + 1, len(selectedTechniques)):
        ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))
        

model = spacy.load(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaCtiAll/model-updated/')

examples = json.load(open('action_sentence.json'))

dataset_report_ttps = json.load(open('report_sentences_with_prediction_v2.json'))
reports = list(set([x['report'] for x in dataset_report_ttps]))



all_feature_sets_all_thresholds = []


for prediction_threshold in range(5, 100, 5):
    print('prediction threshold = ', prediction_threshold)
    all_feature_sets = {}
    all_feature_sets['prediction_probability_threshold'] = prediction_threshold
    all_feature_sets['features'] = []
    
    # for rep in reports:
    for idx in tqdm.tqdm(range(len(reports[:]))):
        rep = reports[idx]
        report_sentences = [x for x in dataset_report_ttps if x['report'] == rep ]
                
        feature_set = {}
        feature_set['report-id'] = rep
        feature_set['pair-wise'] = []
        

        for idx in range(len(ttp_pairs)):
            pair = ttp_pairs[idx]
            te1 = pair[0]
            te2 = pair[1]
            
            features = {}
            features['T1'] = te1['id']
            features['T2'] = te2['id']
            
            sentences_having_te1 = []
            sentences_having_te2 = []
            sentences_having_te1_te2 = []
            
            for sent in report_sentences:
                pred_te1 = [x['prob'] for x in sent['ttps'] if x['id'] == te1['id']][0]
                pred_te2 = [x['prob'] for x in sent['ttps'] if x['id'] == te2['id']][0]
                
                if pred_te1 >= prediction_threshold and pred_te2 >= prediction_threshold:
                    sentences_having_te1_te2.append(sent)
            
            features[f'count_of_same_sentence'] = len(sentences_having_te1_te2)
                
            feature_set['pair-wise'].append(features)
            
        
        all_feature_sets['features'].append(feature_set)
    all_feature_sets_all_thresholds.append(all_feature_sets)
            
json.dump( all_feature_sets_all_thresholds, open( f'json_outputs_v2/same_sentence_v2.json', 'w' ) )