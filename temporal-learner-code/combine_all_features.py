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

def calculate_top_n_highest_probability_technique_pair_report(sentences, t1Id, t2Id, example, t1_prob, t2_prob):    
    top_five_prob_t1, top_five_prob_t2 = [], []
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
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
    else:
        top_five_prob_t1, top_five_prob_t2 = [0,0,0,0,0], [0,0,0,0,0]
        for idx in range(5):
            example[f'T1_P{idx}'] = round(top_five_prob_t1[idx], 2)
            example[f'T2_P{idx}'] = round(top_five_prob_t2[idx], 2)
    return 

def calculate_next_discourse_pair_report(next_sentence_discourses, t1Id, t2Id, example, t1_prob, t2_prob):
    
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
    
        next_sentence_discourse_this_pair = [x for x in next_sentence_discourses if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
            
        example['ELABORATION_NEXT'] = next_sentence_discourse_this_pair['ELABORATION']
        example['IF_ELSE_NEXT'] = next_sentence_discourse_this_pair['IF_ELSE']
        example['LIST_NEXT'] = next_sentence_discourse_this_pair['LIST']
        example['MISC_NEXT'] = next_sentence_discourse_this_pair['MISC']
        example['NEXT_NEXT'] = next_sentence_discourse_this_pair['NEXT']
    
    else:
        example['ELABORATION_NEXT'] = 0
        example['IF_ELSE_NEXT'] = 0
        example['LIST_NEXT'] = 0
        example['MISC_NEXT'] = 0
        example['NEXT_NEXT'] = 0
    
    return

def calculate_coref_discourse_pair_report(coref_sentence_discourses, t1Id, t2Id, example, t1_prob, t2_prob):
    
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
    
        next_sentence_discourse_this_pair = [x for x in coref_sentence_discourses if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
            
        example['ELABORATION_COREF'] = next_sentence_discourse_this_pair['ELABORATION']
        example['IF_ELSE_COREF'] = next_sentence_discourse_this_pair['IF_ELSE']
        example['LIST_COREF'] = next_sentence_discourse_this_pair['LIST']
        example['MISC_COREF'] = next_sentence_discourse_this_pair['MISC']
        example['NEXT_COREF'] = next_sentence_discourse_this_pair['NEXT']
    
    else:
        example['ELABORATION_COREF'] = 0
        example['IF_ELSE_COREF'] = 0
        example['LIST_COREF'] = 0
        example['MISC_COREF'] = 0
        example['NEXT_COREF'] = 0
    
    return

def calculate_timeML_pair_report(timeML_relations, t1Id, t2Id, example, t1_prob, t2_prob):
    
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
    
        timeML_relation_this_pair = [x for x in timeML_relations if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
        keys = list(set(timeML_relation_this_pair.keys()) - set(['T1', 'T2']))
        for k in keys:
            example[f'{k}_TIMEML'] = timeML_relation_this_pair[k]
    
    else:
        timeML_relation_this_pair = timeML_relations[0]
        keys = list(set(timeML_relation_this_pair.keys()) - set(['T1', 'T2']))
        for k in keys:
            example[f'{k}_TIMEML'] = 0
    return

def calculate_rule_mining_metrics_pair_report(rule_mining_features, t1Id, t2Id, example):
    rule_mining_features_this_pair = [x for x in rule_mining_features if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
    keys = list(set(rule_mining_features_this_pair.keys()) - set(['T1', 'T2']))
    for k in keys:
        v = round(rule_mining_features_this_pair[k], 2)
        example[f'{k}_AMR'] = v
    return

def calculate_consecutive_sentence_feature_pair_report(consecutive_sentence_features, t1Id, t2Id, example, t1_prob, t2_prob):
    
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
    
        consecutive_sentence_features_this_pair = [x for x in consecutive_sentence_features if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
            
        example['consecutive_sentence_n1'] = consecutive_sentence_features_this_pair['consecutive_sentence_n1']
        example['consecutive_sentence_n2'] = consecutive_sentence_features_this_pair['consecutive_sentence_n2']
        example['consecutive_sentence_n3'] = consecutive_sentence_features_this_pair['consecutive_sentence_n3']
        example['consecutive_sentence_n4'] = consecutive_sentence_features_this_pair['consecutive_sentence_n4']
        example['consecutive_sentence_n5'] = consecutive_sentence_features_this_pair['consecutive_sentence_n5']
        
        example['consecutive_sentence_p1'] = consecutive_sentence_features_this_pair['consecutive_sentence_p1']
        example['consecutive_sentence_p2'] = consecutive_sentence_features_this_pair['consecutive_sentence_p2']
        example['consecutive_sentence_p3'] = consecutive_sentence_features_this_pair['consecutive_sentence_p3']
        example['consecutive_sentence_p4'] = consecutive_sentence_features_this_pair['consecutive_sentence_p4']
        example['consecutive_sentence_p5'] = consecutive_sentence_features_this_pair['consecutive_sentence_p5']
    
    else:
        example['consecutive_sentence_n1'] = 0
        example['consecutive_sentence_n2'] = 0
        example['consecutive_sentence_n3'] = 0
        example['consecutive_sentence_n4'] = 0
        example['consecutive_sentence_n5'] = 0
        
        example['consecutive_sentence_p1'] = 0
        example['consecutive_sentence_p2'] = 0
        example['consecutive_sentence_p3'] = 0
        example['consecutive_sentence_p4'] = 0
        example['consecutive_sentence_p5'] = 0
    
    return

def calculate_same_coref_cluster_feature_pair_report(coref_clusters, t1Id, t2Id, example,  t1_prob, t2_prob):
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
        coref_cluster_this_pair = [x for x in coref_clusters if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
            
        example['same_coreference_cluster'] = coref_cluster_this_pair['same_coreference_cluster']
    else:
        example['same_coreference_cluster'] = 0
    
    return

def calculate_similarity_feature_pair_report(similarity, t1Id, t2Id, example, t1_prob, t2_prob):
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
        similarity_this_pair = [x for x in similarity if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
            
        example['similarity'] = round(similarity_this_pair['similarity'], 2)
    else:
        example['similarity'] = 0
    
    return

def calculate_time_signal_heuristics_feature_pair_report(time_signal_heuristics, t1Id, t2Id, example, t1_prob, t2_prob):
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
        time_signal_heuristics_this_pair = [x for x in time_signal_heuristics if (x['T1'] == t1Id and x['T2'] == t2Id) or (x['T1'] == t2Id and x['T2'] == t1Id) ][0]
            
        example['heuristic_next'] = round(time_signal_heuristics_this_pair['heuristic_next'], 2)
        example['heuristic_overlap'] = round(time_signal_heuristics_this_pair['heuristic_overlap'], 2)
        example['heuristic_concurrent'] = round(time_signal_heuristics_this_pair['heuristic_concurrent'], 2)
    else:
        example['heuristic_next'] = 0
        example['heuristic_overlap'] = 0
        example['heuristic_concurrent'] = 0
    
    return

def calculate_same_sentence(sentences, t1Id, t2Id, example, t1_prob, t2_prob):
    
    if t1_prob >= example['threshold'] and t2_prob >= example['threshold']:
    
        sentences_having_te1_te2 = []
            
        for sent in sentences:
            pred_te1 = [x['prob'] for x in sent['ttps'] if x['id'] == t1Id][0]
            pred_te2 = [x['prob'] for x in sent['ttps'] if x['id'] == t2Id][0]
            
            if pred_te1 >= prediction_threshold and pred_te2 >= prediction_threshold:
                sentences_having_te1_te2.append(sent)
            
        example[f'same_sentence'] = len(sentences_having_te1_te2)
    else:
        example[f'same_sentence'] = 0
    
    return

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

PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2
PATH_TO_ALL_TEMPORAL_FEATURES = 'unseen_reports_features/all_reports_threshold_95.json' # temporal_features_v2/all_reports_threshold_{prediction_threshold}_v3.json


dataset_report_ttps = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))
reports = list(set([x['report'] for x in dataset_report_ttps]))


examples_all_threshold = []

for prediction_threshold in range(95, 90, -5):
    print('threshold = ', prediction_threshold)
    examples = []
    
    PATH_TO_NEXT_SENTENCE_DISCOURSE_FEATURE = 'unseen_reports_features/unseen_reports_next_sentence_discourse_features_95.json' # Features_v2/next_sentence_discourse_features_{prediction_threshold}_v2.json
    PATH_TO_NEXT_COREF_SENTENCE_DISCOURSE_FEATURE = 'unseen_reports_features/unseen_reports_next_sentence_discourse_coref_features_95.json' # Features_v2/coref_sentence_discourse_features_{prediction_threshold}_coref_v2.json
    PATH_TO_TIMEML_FEATURE = 'unseen_reports_features/timeml_features_95.json' # Features_v2/timeML_features_{prediction_threshold}_v2.json
    PATH_TO_AMR_FEATURE = 'unseen_reports_features/unseen_reports_rule_mining_features.json' # FFeatures/rule_mining_features.json
    PATH_TO_CONSECUTIVE_SENTENCE_FEATURE = 'unseen_reports_features/unseen_reports_consecutive_sentence_features_95.json' # Features_v2/consecutive_sentence_threshold_{prediction_threshold}_v2.json
    PATH_TO_COREFERENCE_CLUSTER_FEATURE = 'unseen_reports_features/unseen_reports_same_coreference_cluster_features_95.json' # Features_v2/same_coreference_cluster_feature_threshold_{prediction_threshold}_v2.json
    PATH_TO_SENTENCE_SIMILARITY_FEATURE = 'unseen_reports_features/unseen_reports_sentence_similarity_features_95.json' # Features_v2/sentence_similarity_feature_threshold_{prediction_threshold}_v2.json
    PATH_TO_TIME_SIGNAL_HEURISTICS_FEATURE = 'unseen_reports_features/unseen_reports_time_signal_heuristics_features_95.json' # Features_v2/heuristics_time_signals_{prediction_threshold}_v2.json
    
    dataset_timeML = json.load(open(f'{PATH_TO_TIMEML_FEATURE}'))
    
    dataset_next_sentence_discourse = json.load(open(f'{PATH_TO_NEXT_SENTENCE_DISCOURSE_FEATURE}'))
    dataset_coref_sentence_discourse = json.load(open(f'{PATH_TO_NEXT_COREF_SENTENCE_DISCOURSE_FEATURE}'))
    dataset_rule_mining_features = json.load(open(f'{PATH_TO_AMR_FEATURE}'))
    dataset_consecutive_sentence = json.load(open(f'{PATH_TO_CONSECUTIVE_SENTENCE_FEATURE}'))['features']
    dataset_coref_cluster = json.load(open(f'{PATH_TO_COREFERENCE_CLUSTER_FEATURE}'))['features']
    dataset_similarity = json.load(open(f'{PATH_TO_SENTENCE_SIMILARITY_FEATURE}'))['features']
    dataset_time_signal_heuristics = json.load(open(f'{PATH_TO_TIME_SIGNAL_HEURISTICS_FEATURE}'))['features']
    
    FAILED = 0
    failed_reports = []
    
    for idx in tqdm.tqdm(range(len(reports[:]))):
        try:
            rep = reports[idx]
            
            sentences = [x for x in dataset_report_ttps if x['report'] == rep]
            
            next_sentence_discourses = [x for x in dataset_next_sentence_discourse if x['report-id'] == rep]
            if len(next_sentence_discourses) > 0:
                next_sentence_discourses = next_sentence_discourses[0]['pair-wise']
            else:
                FAILED += 1
                print('next discourse failed')
                continue
            
            coref_sentence_discourses = [x for x in dataset_coref_sentence_discourse if x['report-id'] == rep]
            if len(coref_sentence_discourses) > 0:
                coref_sentence_discourses = coref_sentence_discourses[0]['pair-wise']
            else:
                FAILED += 1
                print('next discourse coref failed')
                continue
            
            
            timeML_relations = [x for x in dataset_timeML if x['report-id'] == rep or (x['report-id'][:-1] == rep and x['report-id'][-1] == '.')]
            if len(timeML_relations) > 0:
                timeML_relations = timeML_relations[0]['pair-wise']
            else:
                FAILED += 1
                # print('timeml failed')
                continue
            
            rule_mining_features = [x for x in dataset_rule_mining_features if x['report'] == rep][0]['pair-wise']
            
            
            consecutive_sentence_features = [x for x in dataset_consecutive_sentence if x['report-id'] == rep]
            if len(consecutive_sentence_features) > 0:
                consecutive_sentence_features = consecutive_sentence_features[0]['pair-wise']
            else:
                FAILED += 1
                print('consecutive sentence failed')
                continue
            
            coref_clusters = [x for x in dataset_coref_cluster if x['report-id'] == rep]
            if len(coref_clusters) > 0:
                coref_clusters = coref_clusters[0]['pair-wise']
            else:
                FAILED += 1
                print('coref cluster failed')
                continue
            
            similarity = [x for x in dataset_similarity if x['report-id'] == rep]
            if len(similarity) > 0:
                similarity = similarity[0]['pair-wise']
            else:
                FAILED += 1
                print('similarity failed')
                continue
            
            time_signal_heuristics = [x for x in dataset_time_signal_heuristics if x['report-id'] == rep]
            if len(time_signal_heuristics) > 0:
                time_signal_heuristics = time_signal_heuristics[0]['pair-wise']
            else:
                FAILED += 1
                print('time signal failed')
                continue
            
            ###
            ttp_probs = {}
            for te in selectedTechniques:
                te_probs = []    
                for s in sentences:
                    for ttp in s['ttps']:
                        if te['id'] == ttp['id']:
                            te_probs.append(ttp['prob'])
                te_probs.sort(reverse=True)
                ttp_probs[f'{te["id"]}'] = te_probs[0]
            ###
            
            for pair in ttp_pairs[:]:
                example = {}
                example['report'] = rep
                example['threshold'] = prediction_threshold
                
                t1, t2 = pair[0], pair[1]
                t1Id, t2Id = t1['id'], t2['id']
                example['T1'], example['T2'] = t1Id, t2Id
                
                t1_prob, t2_prob = ttp_probs[f'{t1Id}'], ttp_probs[f'{t2Id}']
                
                calculate_top_n_highest_probability_technique_pair_report(sentences, t1Id, t2Id, example, t1_prob, t2_prob)
                calculate_next_discourse_pair_report(next_sentence_discourses, t1Id, t2Id, example, t1_prob, t2_prob)
                calculate_coref_discourse_pair_report(coref_sentence_discourses, t1Id, t2Id, example, t1_prob, t2_prob)
                calculate_timeML_pair_report(timeML_relations, t1Id, t2Id, example, t1_prob, t2_prob)
                calculate_rule_mining_metrics_pair_report(rule_mining_features, t1Id, t2Id, example)
                calculate_consecutive_sentence_feature_pair_report(consecutive_sentence_features, t1Id, t2Id, example, t1_prob, t2_prob)
                calculate_same_coref_cluster_feature_pair_report(coref_clusters, t1Id, t2Id, example, t1_prob, t2_prob)
                calculate_similarity_feature_pair_report(similarity, t1Id, t2Id, example, t1_prob, t2_prob)
                
                calculate_time_signal_heuristics_feature_pair_report(time_signal_heuristics, t1Id, t2Id, example, t1_prob, t2_prob)
                
                calculate_same_sentence(sentences, t1Id, t2Id, example, t1_prob, t2_prob)
        
                examples.append(example)

        except:
            failed_reports.append(reports[idx])
            FAILED += 1

    
    
    print(f'{FAILED} failed ...')
    json.dump( examples, open( f'{PATH_TO_ALL_TEMPORAL_FEATURES}', 'w' ) )
    print('****\n')
    
    print(f'failed reports: {failed_reports}')
# json.dump( examples_all_threshold, open( f'temporal_features/all_reports_all_threshold.json', 'w' ) )