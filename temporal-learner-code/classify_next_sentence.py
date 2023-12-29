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

from tqdm import tqdm

# logging.basicConfig(level=logging.INFO)
# transformers_logger = logging.getLogger("transformers")
# transformers_logger.setLevel(logging.WARNING)

model = ClassificationModel("roberta", '/Users/rayhanurrahman/Workspace/DIscourse-Classifiers/discourse-relation/next_sentence/', use_cuda=False, args={'disable_tqdm':  True})
labels = model.config.id2label

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques = json.load(file)
techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']


PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentence_with_prediction_v2
PATH_TO_NEXT_SENTENCE_PREDICTION = 'unseen_reports_features/predicted_discourse_relations.json' # predicted_discourse_relations.json

examples = json.load(open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}'))

reports = list(set([ex['report'] for ex in examples]))
print(len(reports))

discourse_relation_of_pairs = []

for c in range(len(reports)):
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
    
    for idx in range(0, len(sentences) - 1):
        s1 = sentences[idx]['text']
        s2 = sentences[idx + 1]['text']

        prediction, raw_output = model.predict([[s1, s2]])        
        prediction = labels[prediction[0]]
        
        pair_relation['relations'].append({
            'S1': idx, 'S2': idx + 1, 'relation': prediction
        })
    discourse_relation_of_pairs.append(pair_relation)
    print(f'{c} of {len(reports)} completed...')
    


json.dump(discourse_relation_of_pairs, open(f'{PATH_TO_NEXT_SENTENCE_PREDICTION}', 'w') )
