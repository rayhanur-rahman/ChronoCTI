import os
import pandas as pd
import spacy, json
import tqdm

# pip install https://github.com/explosion/spacy-experimental/releases/download/v0.6.1/en_coreference_web_trf-3.4.0a2-py3-none-any.whl

nlp = spacy.load('en_core_web_trf')
coref = spacy.load("en_coreference_web_trf")


PATH_TO_CTI_REPORTS = 'unseen_reports' # reports
file_names = os.listdir(f'{PATH_TO_CTI_REPORTS}')
# file_names = [fn for fn in file_names if '.md' in fn]
file_names.sort()

# report_sentences = json.load(open('report_sentences_with_prediction.json'))
PATH_TO_REPORT_SENTENCE_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction.json
report_sentences = json.load(open(f'{PATH_TO_REPORT_SENTENCE_PREDICTION}'))

PATH_TO_COREF_SENTENCE = 'unseen_report_coreferenced_sentences.json' # coreferenced_sentences.json
PATH_TO_COREF_SENTENCE_CLUSTER = 'unseen_report_coreferenced_clusters.json' # coreferenced_clusters.json

coreferenced_examples = []
coreferenced_clusters = []

# for name in file_names[:]:
for idx in tqdm.tqdm(range(len(file_names))):
    
    name = file_names[idx]
        
    fname = ''
    
    if '.md' in name: fname = name[:-3]
    elif '.txt' in name: fname = name[:-4]
    else: continue
    
    sentences_in_this_report = [x for x in report_sentences if x['report'] == fname ]
    sentences = [x['text'] for x in sentences_in_this_report]
    text = ' '.join(sentences)
    
    sentenceBoundaries = [ (text.find(s), text.find(s) + len(s)) for s in sentences ]
    sentenceClusters = []
    
    
    doc = coref(text)
    full_clusters = [val for key, val in doc.spans.items() if key.startswith("coref_cluster")]
    for cluster in full_clusters:
        sentenceGroup = []
        for item in cluster:
            # print(f'{item} {item.start_char} {item.end_char} {len(str(item))}')
            
            for idx in range(0, len(sentenceBoundaries)):
                sb = sentenceBoundaries[idx]
                if item.start_char >= sb[0] and item.end_char <= sb[1]:
                    if idx not in sentenceGroup: sentenceGroup.append(idx)
                    break
        sentenceClusters.append(sentenceGroup)
            
        # print('')
    
    # sentenceClusters.append([x for x in range(0, len(sentences))])
    
    sentenceClusters = [x for x in sentenceClusters if len(x) > 1]
    
    coreferenced_clusters.append({
        'report': fname,
        'cluster': sentenceClusters
    })
    
    sentencePairs = []
    for sc in sentenceClusters:
        for idx in range(0, len(sc) - 1):
            if sc[idx] != sc[idx + 1] - 1:
                sentencePairs.append((sc[idx], sc[idx+1]))
                # print(f'{sc[idx]}::{sc[idx+1]}')
        # print('...')
    
    # print(len(sentencePairs))
    sentencePairs = list(set(sentencePairs))
    # print(len(sentencePairs))
    
    sentencePairs.sort(key = lambda v : v[0], reverse = False)
    
    for sp in sentencePairs:
        ex = {
            'report': f'{fname}',
            'S1': sp[0],
            'S2': sp[1],
            'relation': ''
        }

        coreferenced_examples.append(ex)        
    x = 0

with open(f"{PATH_TO_COREF_SENTENCE}", "w") as outfile:
    json.dump(coreferenced_examples, outfile)

with open(f"{PATH_TO_COREF_SENTENCE_CLUSTER}", "w") as outfile:
    json.dump(coreferenced_clusters, outfile)

# pd.read_json('discourse_train_v2_coref.json').to_excel("discourse_train_v2_coref.xlsx")