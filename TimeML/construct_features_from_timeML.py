import os
import random
from typing import Counter
import spacy
import json, statistics, tqdm

# this program takes the timeML json file, and predicts corresponding TTPs from the noun and verb phrases

PATH_TO_THE_SELECTED_TECHNIQUES = 'selected_techniquesWName.json'
PATH_TO_THE_TIMEML_NP_VP_TO_TTPS_PREDICTION = 'unseen_reports_timeML_outputs/timeml_NP_VP_prediction.json'



selectedTechniques = []
file = open(f'{PATH_TO_THE_SELECTED_TECHNIQUES}', 'r')
selectedTechniques = json.load(file)

# selectedTechniques = [x for x in selectedTechniques if x['id'] in ['T1204', 'T1566']]

techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

reports = json.load(open(PATH_TO_THE_TIMEML_NP_VP_TO_TTPS_PREDICTION))

timeML_relation_types = []

for idx in tqdm.tqdm(range(len(reports))):
    report = reports[idx]
    
    relations = report['relations']
    timeML_relation_types.extend( [r['relation'] for r in relations] )
    

timeML_relation_types = list(set(timeML_relation_types))
timeML_relation_types.append('BEGINNED_BY')

ttp_pairs = []

for idx1 in range(len(selectedTechniques)):
    for idx2 in range(len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))
        

timeML_feature_set_all_reports_all_thresholds = []


for prediction_threshold in range(95, 100, 5):
    PATH_TO_TIME_ML_FEATURES_OUTPUT = f'unseen_reports_timeML_outputs/timeml_features_{prediction_threshold}.json'
    print('prediction threshold = ', prediction_threshold)
    timeML_feature_set_all_reports = []
    
    for idx in tqdm.tqdm(range(len(reports))):
        # try:
        report = reports[idx]
        events = []
        sentences = report['sentences']
        relations = report['relations']
        
        for sentence in sentences:
            events.extend(sentence['events'])
        
        ###
        ttp_probs = {}
        for te in selectedTechniques:
            te_probs = []    
            for ev in events:
                for ttp in ev['prediction']:
                    if te['id'] == ttp['id']:
                        te_probs.append(ttp['prob'])
            te_probs.sort(reverse=True)
            
            if len(te_probs) > 0:
                ttp_probs[f'{te["id"]}'] = te_probs[0]
            else:
                ttp_probs[f'{te["id"]}'] = 0
        ###
        
        timeML_feature_set = {}
        timeML_feature_set['report-id'] = report['report-id']
        timeML_feature_set['pair-wise'] = []
        
        # print(feature_set['report-id'])
        
        # for pair in ttp_pairs:
        for idx in range(len(ttp_pairs)):
            pair = ttp_pairs[idx]
            te1 = pair[0]
            te2 = pair[1]
            
            features = {}
            features['T1'] = te1['id']
            features['T2'] = te2['id']
            
            if ttp_probs[f"{te1['id']}"] >= prediction_threshold and ttp_probs[f"{te2['id']}"] >= prediction_threshold:
            
                events_having_te1 = []
                events_having_te2 = []
                relations_having_te1_te2 = []
                relations_having_te2_te1 = []
                
                
                for ev in events:
                    for pred in ev['prediction']:
                        if pred['prob'] >= prediction_threshold:
                            if pred['id'] == te1['id']: 
                                events_having_te1.append(ev)
                            if pred['id'] == te2['id']: 
                                events_having_te2.append(ev)
                
                
                for rel in relations:
                    events_te1_te2 = [e['id'] for e in events_having_te1] + [e['id'] for e in events_having_te2] 
                    
                    # if rel['e1'] in events_te1_te2 and rel['e2'] in events_te1_te2:
                    if (rel['e1'] in [e['id'] for e in events_having_te1] and rel['e2'] in [e['id'] for e in events_having_te2]) :
                        relations_having_te1_te2.append(rel)
                        
                    if (rel['e2'] in [e['id'] for e in events_having_te1] and rel['e1'] in [e['id'] for e in events_having_te2]) :
                        relations_having_te2_te1.append(rel)
                
                for type in timeML_relation_types:
                    count = 0
                    
                    if type in ['IDENTITY', 'SIMULTANEOUS']:
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == type]))
                    
                    if type == 'BEFORE':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'AFTER']))
                    
                    if type == 'AFTER':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'BEFORE']))
                    
                    if type == 'DURING':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'DURING_INV']))
                    
                    if type == 'DURING_INV':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'DURING']))
                    
                    if type == 'BEGINS':
                        count = len([r for r in relations_having_te1_te2 if r['relation'] == type])
                    
                    if type == 'BEGINNED_BY':
                        count = len([r for r in relations_having_te2_te1 if r['relation'] == 'BEGINS'])
                        
                    if type == 'ENDED_BY':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'ENDS']))
                    
                    if type == 'ENDS':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'ENDED_BY']))
                    
                    if type == 'INCLUDES':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'IS_INCLUDED']))
                    
                    if type == 'IS_INCLUDED':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'INCLUDES']))
                    
                    if type == 'IBEFORE':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'IAFTER']))
                    
                    if type == 'IAFTER':
                        count = max(len([r for r in relations_having_te1_te2 if r['relation'] == type]) , len([r for r in relations_having_te2_te1 if r['relation'] == 'IBEFORE']))
                    
                    features[f'{type}'] = count
            
            else:
                for type in timeML_relation_types:
                    features[f'{type}'] = 0
            
            timeML_feature_set['pair-wise'].append(features)
            
        
        timeML_feature_set_all_reports.append(timeML_feature_set)
    
        # except:
        #     pass
            
    json.dump( timeML_feature_set_all_reports, open( f'{PATH_TO_TIME_ML_FEATURES_OUTPUT}', 'w' ) )