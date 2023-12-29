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

# selectedTechniques = [x for x in selectedTechniques if x['id'] in ['T1204', 'T1566']]

techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

ttp_pairs = []


for idx1 in range(len(selectedTechniques)):
    for idx2 in range(len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))


model = spacy.load(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaCtiAll/model-updated/')

PATH_TO_CTI_REPORTS_SENTENCES = 'unseen_report_sentence.json' # action_sentence.json
PATH_TO_CTI_REPORTS_SENTENCES_WITH_METADATA = 'unseen_report_sentence_with_metadata.json' # report_sentences.json
PATH_TO_TTPS_PREDICTION_OUTPUT_AS_DIRECTORY = 'unseen_reports_prediction' # results3/
PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2
PATH_TO_CONSECUTIVE_SENTENCE_FEATURE = 'unseen_reports_features/unseen_reports_consecutive_sentence_features_95.json' # Features_v2/consecutive_sentence_threshold_95_v2.json

examples = json.load(open(f'{PATH_TO_CTI_REPORTS_SENTENCES}'))

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
            
            next_sentence_pair = {}
            next_sentence_pair['n1'] = []
            next_sentence_pair['n2'] = []
            next_sentence_pair['n3'] = []
            next_sentence_pair['n4'] = []
            next_sentence_pair['n5'] = []
            
            previous_sentence_pair = {}
            previous_sentence_pair['p1'] = []
            previous_sentence_pair['p2'] = []
            previous_sentence_pair['p3'] = []
            previous_sentence_pair['p4'] = []
            previous_sentence_pair['p5'] = []
            
            if ttp_probs[f"{te1['id']}"] >= prediction_threshold and ttp_probs[f"{te2['id']}"] >= prediction_threshold:
            
                for n in range(1, 6):
                    for sent_idx in range(len(report_sentences)):
                        if sent_idx + n < len(report_sentences):
                            next_sentence_pair[f'n{n}'].append( (sent_idx, sent_idx + n) )
                
                for n in range(1, 6):
                    for sent_idx in range(len(report_sentences)):
                        if sent_idx - n >= 0:
                            previous_sentence_pair[f'p{n}'].append( (sent_idx, sent_idx - n) )
                
                
                for n in range(1, 6):
                    count = 0
                    pairs = next_sentence_pair[f'n{n}']
                    for pair in pairs:
                        pred_te1 = [x['prob'] for x in report_sentences[pair[0]]['ttps'] if x['id'] == te1['id']][0]
                        pred_te2 = [x['prob'] for x in report_sentences[pair[1]]['ttps'] if x['id'] == te2['id']][0]
                        if pred_te1 >= prediction_threshold and pred_te2 >= prediction_threshold:
                            count += 1

                    features[f'consecutive_sentence_n{n}'] = count
                    
                for n in range(1, 6):
                    count = 0
                    pairs = previous_sentence_pair[f'p{n}']
                    for pair in pairs:
                        pred_te1 = [x['prob'] for x in report_sentences[pair[0]]['ttps'] if x['id'] == te1['id']][0]
                        pred_te2 = [x['prob'] for x in report_sentences[pair[1]]['ttps'] if x['id'] == te2['id']][0]
                        if pred_te1 >= prediction_threshold and pred_te2 >= prediction_threshold:
                            count += 1
            
                    features[f'consecutive_sentence_p{n}'] = count
            
            else:
                for n in range(1, 6):            
                    features[f'consecutive_sentence_p{n}'] = 0
                    features[f'consecutive_sentence_n{n}'] = 0
            
            feature_set['pair-wise'].append(features)
            
        
        all_feature_sets['features'].append(feature_set)
    all_feature_sets_all_thresholds.append(all_feature_sets)
            
    json.dump( all_feature_sets, open( f'{PATH_TO_CONSECUTIVE_SENTENCE_FEATURE}', 'w' ) )
# json.dump( all_feature_sets_all_thresholds, open( f'json_outputs/consecutive_sentence.json', 'w' ) )