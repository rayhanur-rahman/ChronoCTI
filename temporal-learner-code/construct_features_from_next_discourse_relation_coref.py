import os
import random
from typing import Counter
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

PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2
PATH_TO_NEXT_SENTENCE_COREF_PREDICTION = 'unseen_reports_features/predicted_discourse_relations_coref.json' # predicted_discourse_relations_coref.json
PATH_TO_NEXT_DISCOURSE_RELATION_COREF_FEATURE = 'unseen_reports_features/unseen_reports_next_sentence_discourse_coref_features_95.json' # Features_v2/coref_sentence_discourse_features_95_coref_v2.json

dataset_discourse_relation = json.load(open(f'{PATH_TO_NEXT_SENTENCE_COREF_PREDICTION}'))
dataset_report_ttps = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))


count = 0

relation_types = []

for idx in tqdm.tqdm(range(len(dataset_discourse_relation))):
    example = dataset_discourse_relation[idx]
    
    relations = example['relations']
    relation_types.extend( [r['relation'] for r in relations] )
    

relation_types = list(set(relation_types))
        

all_feature_sets_all_thresholds = []


for prediction_threshold in range(95, 100, 5):
    print('prediction threshold = ', prediction_threshold)
    all_feature_sets = []

    for idx in tqdm.tqdm(range(len(dataset_discourse_relation))):
        example = dataset_discourse_relation[idx]
        relations = example['relations']
        sentences = [x for x in dataset_report_ttps if x['report'] == example['report']]
                
        feature_set = {}
        feature_set['report-id'] = example['report']
        feature_set['pair-wise'] = []
        
        ttp_probs = {}
        for te in selectedTechniques:
            te_probs = []    
            for s in sentences:
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
                relations_having_te1_te2 = []
                
                
                for sent in sentences:
                    for pred in sent['ttps']:
                        if pred['prob'] >= prediction_threshold:
                            if pred['id'] == te1['id']: 
                                sentences_having_te1.append(sent)
                            if pred['id'] == te2['id']: 
                                sentences_having_te2.append(sent)
                
                for rel in relations:
                    if rel['S1'] in [e['line'] for e in sentences_having_te1] and rel['S2'] in [e['line'] for e in sentences_having_te2]:
                        relations_having_te1_te2.append(rel)
                
                for type in relation_types:
                    count = 0
                    for rel in relations_having_te1_te2:
                        if rel['relation'] == type:
                            count += 1

                    features[f'{type}'] = count
            else:
                for type in relation_types:
                    features[f'{type}'] = 0
                
            feature_set['pair-wise'].append(features)
            
        
        all_feature_sets.append(feature_set)
            
    json.dump( all_feature_sets, open( f'{PATH_TO_NEXT_DISCOURSE_RELATION_COREF_FEATURE}', 'w' ) )