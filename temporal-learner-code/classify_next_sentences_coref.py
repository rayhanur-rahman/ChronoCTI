import os
import random
import spacy
import spacy_transformers
import json, statistics, tqdm
import pandas as pd
import logging
from simpletransformers.classification import (
    ClassificationModel, ClassificationArgs
)

# logging.basicConfig(level=logging.INFO)
# transformers_logger = logging.getLogger("transformers")
# transformers_logger.setLevel(logging.WARNING)

model = ClassificationModel("roberta", '/Users/rayhanurrahman/Workspace/DIscourse-Classifiers/discourse-relation/coref/', use_cuda=False, args={'disable_tqdm':  True})
labels = model.config.id2label

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques = json.load(file)
techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentence_with_prediction_v2
PATH_TO_COREF_SENTENCE_DATASET = 'unseen_report_coreferenced_sentences.json' # coreferenced_sentences.json
PATH_TO_NEXT_SENTENCE_COREF_PREDICTION = 'unseen_reports_features/predicted_discourse_relations_coref.json' # predicted_discourse_relations_coref.json


examples = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))
coreferred_sentences_dataset = json.load(open(f'{PATH_TO_COREF_SENTENCE_DATASET}'))

reports = list(set([ex['report'] for ex in examples]))

discourse_relation_of_pairs = []

for c in range(len(reports)):
# for rep in reports:
    rep = reports[c]
    sentences = []
    print(rep)
    
    for ex in examples:
        if ex['report'] == rep:
            sentences.append(ex)
    
    sentences.sort(key = lambda v : v['line'])
    
    
    pair_relation = {}
    pair_relation['report'] = rep
    pair_relation['relations'] = []
    
    for item in coreferred_sentences_dataset:
        if item['report'] == f'{rep}':

            s1 = sentences[item['S1']]['text']
            s2 = sentences[item['S2']]['text']

            prediction, raw_output = model.predict([[s1, s2]])        
            prediction = labels[prediction[0]]
            
            pair_relation['relations'].append({
                'S1': item['S1'], 'S2': item['S2'], 'relation': prediction
            })
    discourse_relation_of_pairs.append(pair_relation)
        
    print(f'{c} of {len(reports)} completed...')

json.dump(discourse_relation_of_pairs, open(f'{PATH_TO_NEXT_SENTENCE_COREF_PREDICTION}', 'w') )
