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
    for idx2 in range(len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))
        

model = spacy.load(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaCtiAll/model-best/')

PATH_TO_CTI_REPORTS_SENTENCES = 'unseen_report_sentence.json' # action_sentence.json
PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2
PATH_TO_COREFERENCE_CLUSTERS = 'unseen_report_coreferenced_clusters.json' # coreferenced_clusters.json
PATH_TO_COREF_CLUSTER_SENTENCE_FEATURE = 'unseen_reports_features/unseen_reports_same_coreference_cluster_features_95.json' # Features_v2/same_coreference_cluster_feature_threshold_95_v2.json

examples = json.load(open(f'{PATH_TO_CTI_REPORTS_SENTENCES}'))

dataset_report_ttps = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))
dataset_coref_clusters = json.load(open(f'{PATH_TO_COREFERENCE_CLUSTERS}'))
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
        report_clusters = [c for c in dataset_coref_clusters if c['report'] == f'{rep}' ][0]
                
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
            
                count_same_cluster = 0
                for cluster in report_clusters['cluster']:
                    preds_te1 = []
                    preds_te2 = []

                    for cl in cluster:
                        preds_te1.append( [ x['prob'] for x in report_sentences[cl]['ttps'] if x['id'] == te1['id'] ][0] )
                        preds_te2.append( [ x['prob'] for x in report_sentences[cl]['ttps'] if x['id'] == te2['id'] ][0] )

                        max_pred_prob_te1 = max(preds_te1)
                        max_pred_prob_te2 = max(preds_te2)
                        
                        if max_pred_prob_te1 >= prediction_threshold and max_pred_prob_te2 >= prediction_threshold:
                            count_same_cluster += 1
                                
                features[f'same_coreference_cluster'] = count_same_cluster
            
            else:
                features[f'same_coreference_cluster'] = 0
            
            feature_set['pair-wise'].append(features)
            
        
        all_feature_sets['features'].append(feature_set)
    all_feature_sets_all_thresholds.append(all_feature_sets)
            
    json.dump( all_feature_sets, open( f'{PATH_TO_COREF_CLUSTER_SENTENCE_FEATURE}', 'w' ) )
# json.dump( all_feature_sets_all_thresholds, open( f'json_outputs/consecutive_sentence.json', 'w' ) )