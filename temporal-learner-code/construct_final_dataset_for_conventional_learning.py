import json
import math
import pandas as pd
import random
import tqdm
import pickle
import numpy as np

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

random.seed(0)

for prediction_threshold in range(5, 100, 5):
    print(f'prediction_threshold == {prediction_threshold}')
    dataset = json.load( open(f'temporal_features/all_reports_threshold_{prediction_threshold}.json') )
    random.shuffle(dataset)
    # dataset = random.sample(dataset, round(len(dataset)*0.0005))
    # json.dump(dataset, open('minified_dataset.json', 'w'))

    # dataset = json.load( open('minified_dataset.json') )

    # print(len(dataset))

    df_labels = pd.read_excel('temporal_relation_dataset.xlsx')

    print(df_labels.shape)

    identifiers = ['report', 'T1', 'T2', 'threshold']
    features = list(set(dataset[0].keys()) - set(['T1', 'T2', 'report', 'threshold']))
    labels = ['CONCURRENT', 'NEXT', 'NULL', 'OVERLAP']

    for idx, row in df_labels.iterrows():
        if row['relation'] in ['CONCURRENT', 'OVERLAP']:
            kv = {
                'report': [row['report']],
                'relation': [row['relation']],
                'T1': [row['T2']],
                'T2': [row['T1']],
                
            }
            df_labels = pd.concat([df_labels, pd.DataFrame(kv)], ignore_index=True)
            df_labels.reset_index()

    print(df_labels.shape)

    df_labels['T1Id'] = df_labels['T1'].apply(lambda x : str(x)[:5] )
    df_labels['T2Id'] = df_labels['T2'].apply(lambda x : str(x)[:5] )

    print(df_labels.shape)


    kv_list = []

    for idx in tqdm.tqdm(range(len(dataset[:]))):
        data = dataset[idx]
        rep = data['report']
        T1 = data['T1']
        T2 = data['T2']
        threshold = data['threshold']
        
        df_labels_q = df_labels.query(f' report == "{rep}" and T1Id == "{T1}" and T2Id == "{T2}"')
        kv = {}
        if len(df_labels_q) > 0:
            for item in identifiers:
                kv[item] = data[item]
            for item in features:
                kv[item] = data[item]
            
            
            for index, row in df_labels_q.iterrows():
                for item in labels:
                    if row['relation'] == item:
                        kv[item] = 1
                    else:
                        kv[item] = 0
            
        else:
            for item in identifiers:
                kv[item] = data[item]
            for item in features:
                kv[item] = data[item]
            for item in labels:
                kv[item] = 0
            kv['NULL'] = 1
        
        kv_list.append(kv)

    dataset_df = pd.DataFrame.from_dict(kv_list)

    dataset_df.to_pickle(f"dataset_df_threshold_{prediction_threshold}.pkl")

    print(dataset_df.shape)
    # print(dataset_df.head())
    print('next = ', len(dataset_df.query(f'NEXT == 1')))
    print('overlap = ', len(dataset_df.query(f'OVERLAP == 1')))
    print('concurrent = ', len(dataset_df.query(f'CONCURRENT == 1')))
    print('null = ', len(dataset_df.query(f'NULL == 1')))
    print('')
    
    
input('enter something')


positive_examples = []
negative_examples = []

reports = list(set([x for x in df_labels['report'].tolist()]))
reports.sort()




# We need to sample dataset to prevent class imbalanced
# Many ways to do this. Here we first find out the positive techniques from a report, and based on that, generate all possible pairs
# this way, instead of 120*120 pairs per report, we might only have 20*20 pairs. 

for idx in tqdm.tqdm(range(len(reports))):
    rep = reports[idx]
    dfq = df_labels.query(f' report == "{rep}" ')
    allTechniques = dfq['T1Id'].tolist()
    allTechniques.extend(dfq['T2Id'].tolist())
    allTechniques = list(set(allTechniques))
    allTechniques = [x for x in allTechniques if len(str(x)) == 5]
    
    # techniquesNotPresent = list(set([x['id'] for x in selectedTechniques]) - set(allTechniques))
        
    for item1 in allTechniques:
        for item2 in allTechniques:
            is_really_positive = False
            
            if item1 != item2:
                for idx, row in dfq.iterrows():
                    if (row['T1Id'] == item1 and row['T2Id'] == item2):
                        is_really_positive = True
                        break
                
                if is_really_positive:
                    positive_examples.append({
                        'report': rep,
                        'T1': item1,
                        'T2': item2
                    })
                else:
                    negative_examples.append({
                        'report': rep,
                        'T1': item1,
                        'T2': item2
                    })

print(len(positive_examples))
print(len(negative_examples))

X = []
y = []


for idx in tqdm.tqdm(range(len(positive_examples))):
    item = positive_examples[idx]
    query = [x for x in dataset if x['report'] == item['report'] and x['T1'] == item['T1'] and x['T2'] == item['T2']]

    if len(query):
        data = query[0]
        features = list(set(data.keys()) - set(['T1', 'T2', 'report', 'threshold']))
        example = []
        
        for feature in features:
            example.append(data[feature])
            
        X.append(example)
        y.append(1)


for idx in tqdm.tqdm(range(len(negative_examples))):
    item = negative_examples[idx]
    query = [x for x in dataset if x['report'] == item['report'] and x['T1'] == item['T1'] and x['T2'] == item['T2']]
    
    if len(query):
        data = query[0]
        features = list(set(data.keys()) - set(['T1', 'T2', 'report', 'threshold']))
        example = []
        
        for feature in features:
            example.append(data[feature])
                
        X.append(example)
        y.append(0)

with open('pickle_X.pkl', 'wb') as fp:
    pickle.dump(X, fp, pickle.HIGHEST_PROTOCOL)

with open('pickle_y.pkl', 'wb') as fp:
    pickle.dump(y, fp, pickle.HIGHEST_PROTOCOL)

input('enter something')

# del X
# del y   

X_all = pickle.load( open('pickle_X.pkl', 'rb') )
y_all = pickle.load( open('pickle_y.pkl', 'rb') )

pos_ex_idx = []
neg_ex_idx = []

for idx in range(len(y_all)):
    if y_all[idx] == 0:
        neg_ex_idx.append(idx)
    else:
        pos_ex_idx.append(idx)

neg_ex_idx = random.sample(neg_ex_idx, len(pos_ex_idx))


X = [ X_all[idx] for idx in pos_ex_idx ]
X.extend([ X_all[idx] for idx in neg_ex_idx ])
y = [ y_all[idx] for idx in pos_ex_idx ]
y.extend([ y_all[idx] for idx in neg_ex_idx ])

# X, y = X_all, y_all

for i in range(len(X)):
    for j in range(len(X[i])):
        if np.isinf(X[i][j]):
            X[i][j] = 0

for row in X:
    for col in row:
        if np.isinf(col):
            print('...')
