import os
import random
import spacy
import spacy_transformers
import json, statistics, tqdm


# this program takes the timeML json file, and predicts corresponding TTPs from the noun and verb phrases

PATH_TO_TIMEML_JSON_OUTPUT = 'unseen_reports_timeML_outputs/unseen_reports_timeML_output.json'
PATH_TO_THE_CLASSIFIER = '/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaCtiAll/model-updated/'
PATH_TO_THE_SELECTED_TECHNIQUES = 'selected_techniquesWName.json'
PATH_TO_THE_PREDICTION_JSON_OUTPUT = 'unseen_reports_timeML_outputs/timeml_NP_VP_prediction.json'  


selectedTechniques = []
file = open(PATH_TO_THE_SELECTED_TECHNIQUES, 'r')
selectedTechniques = json.load(file)
techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

model = spacy.load(PATH_TO_THE_CLASSIFIER)

examples = json.load(open(PATH_TO_TIMEML_JSON_OUTPUT))
examples_with_predictions = []

count = 0
for idx in tqdm.tqdm(range(len(examples))):
    example = examples[idx]
    sentences = example['sentences']
    
    for sentence in sentences:
        events = sentence['events']
        
        for ev in events:
            text = ev['phraseText']
            doc = model(text)

            predictions = {}
            
            for key in doc.cats.keys():
                predictions[f'{key}'] = doc.cats[key]

            filteredPredictions = []
            
            for key in predictions.keys():
                filteredPredictions.append((key, predictions[key]))
            
            filteredPredictions.sort(key = lambda v : v[1], reverse = True)
        
            result = []
            
            for item in filteredPredictions:
                result.append({
                    'id': item[0],
                    'name': techniqueDict[item[0]],
                    'prob': 100 * round(item[1], 4),
                })

            ev['prediction'] = result
    
json.dump( examples, open( f'{PATH_TO_THE_PREDICTION_JSON_OUTPUT}', 'w' ) )