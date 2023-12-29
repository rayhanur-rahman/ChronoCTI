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

model = spacy.load(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaCtiAll/model-updated/')
PATH_TO_CTI_REPORTS_SENTENCES = 'unseen_report_sentence.json' # action_sentences.json
PATH_TO_TTPS_PREDICTION_OUTPUT_AS_DIRECTORY = 'unseen_reports_prediction' # results3/

examples = json.load(open(f'{PATH_TO_CTI_REPORTS_SENTENCES}'))

count = 0
for idx in tqdm.tqdm(range(len(examples))):
# for example in examples:
    example = examples[idx]
    text = example['text']
    doc = model(text)

    predictions = {}
            
    for key in doc.cats.keys():
        predictions[f'{key}'] = doc.cats[key]

    filteredPredictions = []
        
    for key in predictions.keys():
        filteredPredictions.append((key, predictions[key]))
        
    filteredPredictions.sort(key = lambda v : v[1], reverse = True)
    
    result = {}
    result['text'] = text
    result['ttps'] = []
    
    for item in filteredPredictions:
        result['ttps'].append({
            'id': item[0],
            'name': techniqueDict[item[0]],
            'prob': 100 * round(item[1], 4),
        })
    

    with open(f"{PATH_TO_TTPS_PREDICTION_OUTPUT_AS_DIRECTORY}/{count}.json", "w") as outfile:
        json.dump(result, outfile)
    
    count += 1