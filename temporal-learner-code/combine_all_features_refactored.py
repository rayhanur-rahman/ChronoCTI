import json
import re
import pandas as pd
import os
import random
import spacy
import spacy_transformers
import json, statistics, tqdm
import subprocess, sys
from numpy.linalg import norm
import numpy as np

def calculate_top_n_highest_probability_technique_pair_report(sentences, t1Id, t2Id, example):    
    top_five_prob_t1, top_five_prob_t2 = [], []
        
    for s in sentences:
        for ttp in s['ttps']:
            if t1Id == ttp['id']:
                top_five_prob_t1.append(ttp['prob'])
            if t2Id == ttp['id']:
                top_five_prob_t2.append(ttp['prob'])
    
    top_five_prob_t1.sort(reverse=True)
    top_five_prob_t2.sort(reverse=True)
    
    for idx in range(5):
        example[f'T1_P{idx}'] = round(top_five_prob_t1[idx], 2)
        example[f'T2_P{idx}'] = round(top_five_prob_t2[idx], 2)
    
    return top_five_prob_t1[0], top_five_prob_t2[0] 

def calculate_next_discourse_pair_report(next_sentence_discourses, t1Id, t2Id, example):
    next_sentence_discourse_this_pair = [x for x in next_sentence_discourses if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
        
    example['ELABORATION_NEXT'] = next_sentence_discourse_this_pair['ELABORATION']
    example['IF_ELSE_NEXT'] = next_sentence_discourse_this_pair['IF_ELSE']
    example['LIST_NEXT'] = next_sentence_discourse_this_pair['LIST']
    example['MISC_NEXT'] = next_sentence_discourse_this_pair['MISC']
    example['NEXT_NEXT'] = next_sentence_discourse_this_pair['NEXT']
    
    return

def calculate_coref_discourse_pair_report(coref_sentence_discourses, t1Id, t2Id, example):
    next_sentence_discourse_this_pair = [x for x in coref_sentence_discourses if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
        
    example['ELABORATION_COREF'] = next_sentence_discourse_this_pair['ELABORATION']
    example['IF_ELSE_COREF'] = next_sentence_discourse_this_pair['IF_ELSE']
    example['LIST_COREF'] = next_sentence_discourse_this_pair['LIST']
    example['MISC_COREF'] = next_sentence_discourse_this_pair['MISC']
    example['NEXT_COREF'] = next_sentence_discourse_this_pair['NEXT']
    
    return

def calculate_timeML_pair_report(timeML_relations, t1Id, t2Id, example):
    timeML_relation_this_pair = [x for x in timeML_relations if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
    keys = list(set(timeML_relation_this_pair.keys()) - set(['T1', 'T2']))
    for k in keys:
        example[f'{k}_TIMEML'] = timeML_relation_this_pair[k]
    return

def calculate_rule_mining_metrics_pair_report(rule_mining_features, t1Id, t2Id, example):
    rule_mining_features_this_pair = [x for x in rule_mining_features if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
    keys = list(set(rule_mining_features_this_pair.keys()) - set(['T1', 'T2']))
    for k in keys:
        example[f'{k}_AMR'] = round(rule_mining_features_this_pair[k], 2)
    return

def calculate_consecutive_sentence_feature_pair_report(consecutive_sentence_features, t1Id, t2Id, example):
    consecutive_sentence_features_this_pair = [x for x in consecutive_sentence_features if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
        
    example['consecutive_sentence_n1'] = consecutive_sentence_features_this_pair['consecutive_sentence_n1']
    example['consecutive_sentence_n2'] = consecutive_sentence_features_this_pair['consecutive_sentence_n2']
    example['consecutive_sentence_n3'] = consecutive_sentence_features_this_pair['consecutive_sentence_n3']
    example['consecutive_sentence_n4'] = consecutive_sentence_features_this_pair['consecutive_sentence_n4']
    example['consecutive_sentence_n5'] = consecutive_sentence_features_this_pair['consecutive_sentence_n5']
    
    return

def calculate_same_coref_cluster_feature_pair_report(coref_clusters, t1Id, t2Id, example):
    coref_cluster_this_pair = [x for x in coref_clusters if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
        
    example['same_coreference_cluster'] = coref_cluster_this_pair['same_coreference_cluster']
    
    return

def calculate_similarity_feature_pair_report(similarity, t1Id, t2Id, example):
    similarity_this_pair = [x for x in similarity if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
        
    example['similarity'] = round(similarity_this_pair['similarity'], 2)
    
    return

def calculate_same_sentence(sentences, t1Id, t2Id, example):
    sentences_having_te1_te2 = []
        
    for sent in sentences:
        pred_te1 = [x['prob'] for x in sent['ttps'] if x['id'] == t1Id][0]
        pred_te2 = [x['prob'] for x in sent['ttps'] if x['id'] == t2Id][0]
        
        if pred_te1 >= prediction_threshold and pred_te2 >= prediction_threshold:
            sentences_having_te1_te2.append(sent)
        
    example[f'same_sentence'] = len(sentences_having_te1_te2)
    return

DIRECTORY_OF_THE_SELECTED_TECHNIQUES = 'selected_techniquesWName.json'
PATH_TO_SENTENCE_TO_TTPS_PREDICTION = 'Features_Dataset/report_sentences_with_prediction.json'
PATH_TO_THE_TIMEML_NP_VP_TO_TTPS_PREDICTION = 'Features_Dataset/timeml_NP_VP_prediction.json' 

selectedTechniques = json.load(open(f'{DIRECTORY_OF_THE_SELECTED_TECHNIQUES}'))

ttp_pairs = []

for idx1 in range(0, len(selectedTechniques)):
    for idx2 in range(0, len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append((selectedTechniques[idx1], selectedTechniques[idx2]))

dataset_report_sentence_ttps = json.load(open(PATH_TO_SENTENCE_TO_TTPS_PREDICTION))
reports = list(set([x['report'] for x in dataset_report_sentence_ttps]))


dataset_timeML_to_TTPs = json.load(open(PATH_TO_THE_TIMEML_NP_VP_TO_TTPS_PREDICTION))

timeML_relation_types = []

for idx in tqdm.tqdm(range(len(dataset_timeML_to_TTPs))):
    item = dataset_timeML_to_TTPs[idx]
    relations = item['relations']
    timeML_relation_types.extend( [r['relation'] for r in relations] )
    

timeML_relation_types = list(set(timeML_relation_types))
timeML_relation_types.append('BEGINNED_BY')


examples_all_threshold = []



for prediction_threshold in range(5, 100, 5):    
    for idx in tqdm.tqdm(range(len(reports[:]))):
        rep = reports[idx]
        
        
        





# for prediction_threshold in range(5, 100, 5):
#     print('threshold = ', prediction_threshold)
#     examples = []
    
    
#     dataset_next_sentence_discourse = json.load(open(f'json_outputs/next_sentence_features_{prediction_threshold}.json'))
#     dataset_coref_sentence_discourse = json.load(open(f'json_outputs/next_sentence_features_{prediction_threshold}_coref.json'))
#     dataset_timeML = json.load(open(f'json_outputs/timeML_features_{prediction_threshold}.json'))
#     dataset_rule_mining_features = json.load(open(f'json_outputs/rule_mining_features.json'))
#     dataset_consecutive_sentence = json.load(open(f'json_outputs/consecutive_sentence_threshold_{prediction_threshold}.json'))['features']
#     dataset_coref_cluster = json.load(open(f'json_outputs/same_coreference_cluster_feature_threshold_{prediction_threshold}.json'))['features']
#     dataset_similarity = json.load(open(f'json_outputs/sentence_similarity_feature_threshold_{prediction_threshold}.json'))['features']
    
#     for idx in tqdm.tqdm(range(len(reports[:]))):
#         rep = reports[idx]
        
#         sentences = [x for x in dataset_report_sentence_ttps if x['report'] == rep]
#         next_sentence_discourses = [x for x in dataset_next_sentence_discourse if x['report-id'] == rep][0]['pair-wise']
#         coref_sentence_discourses = [x for x in dataset_coref_sentence_discourse if x['report-id'] == rep][0]['pair-wise']
#         timeML_relations = [x for x in dataset_timeML if x['report-id'] == rep][0]['pair-wise']
#         rule_mining_features = [x for x in dataset_rule_mining_features if x['report'] == rep][0]['pair-wise']
#         consecutive_sentence_features = [x for x in dataset_consecutive_sentence if x['report-id'] == rep][0]['pair-wise']
#         coref_clusters = [x for x in dataset_coref_cluster if x['report-id'] == rep][0]['pair-wise']
#         similarity = [x for x in dataset_similarity if x['report-id'] == rep][0]['pair-wise']
        
#         for pair in ttp_pairs[:]:
#             example = {}
#             example['report'] = rep
#             example['threshold'] = prediction_threshold
            
#             t1, t2 = pair[0], pair[1]
#             t1Id, t2Id = t1['id'], t2['id']
#             example['T1'], example['T2'] = t1Id, t2Id
            
#             t1_prob, t2_prob = calculate_top_n_highest_probability_technique_pair_report(sentences, t1Id, t2Id, example)
            
#             # if t1_prob >= prediction_threshold or t2_prob >= prediction_threshold:
#             calculate_next_discourse_pair_report(next_sentence_discourses, t1Id, t2Id, example)
#             calculate_coref_discourse_pair_report(coref_sentence_discourses, t1Id, t2Id, example)
#             calculate_timeML_pair_report(timeML_relations, t1Id, t2Id, example)
#             calculate_rule_mining_metrics_pair_report(rule_mining_features, t1Id, t2Id, example)
#             calculate_consecutive_sentence_feature_pair_report(consecutive_sentence_features, t1Id, t2Id, example)
#             calculate_same_coref_cluster_feature_pair_report(coref_clusters, t1Id, t2Id, example)
#             calculate_similarity_feature_pair_report(similarity, t1Id, t2Id, example)
#             calculate_same_sentence(sentences, t1Id, t2Id, example)
    
#             examples.append(example)
#     examples_all_threshold.append(examples) 

#     json.dump( examples, open( f'temporal_features/all_reports_threshold_{prediction_threshold}.json', 'w' ) )
#     print('****\n\n')
# json.dump( examples_all_threshold, open( f'temporal_features/all_reports_all_threshold.json', 'w' ) )