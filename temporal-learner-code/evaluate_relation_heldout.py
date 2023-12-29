import json
import math
import statistics
import pandas as pd
import random
import tqdm
import pickle
import numpy as np
from sklearn.datasets import make_classification
from imblearn.over_sampling import RandomOverSampler
from collections import Counter
from imblearn.over_sampling import SMOTE, ADASYN

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.pipeline import make_pipeline
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import GradientBoostingClassifier, BaggingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report

from skmultilearn.problem_transform import BinaryRelevance
from sklearn.svm import SVC

import torch
from torch import nn
import torch.nn.functional as F
from skorch import NeuralNetClassifier
from imblearn.ensemble import EasyEnsembleClassifier

from sklearn.preprocessing import StandardScaler, MinMaxScaler



df_temporal = pd.read_excel('temporal_relation_dataset.xlsx')

train_reports = list(set(df_temporal.query(' mask == "train" ')['report'].tolist()))
eval_reports = list(set(df_temporal.query(' mask == "eval" ')['report'].tolist()))


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


def apply_binary_mask(row):
    if row.CONCURRENT == 1 or row.NEXT == 1 or row.OVERLAP == 1:
        return 1
    else:
        return 0


dataset : pd.DataFrame = pd.read_pickle(f'dataset_df_threshold_5.pkl')

dataset = dataset.query( f' report in {eval_reports} ' )


dataset = pd.get_dummies(dataset, columns = ['T1', 'T2'])

for te in selectedTechniques:
    dataset[f"T1_{te['id']}"] = dataset[f"T1_{te['id']}"].astype(int)
    dataset[f"T2_{te['id']}"] = dataset[f"T2_{te['id']}"].astype(int)


dataset = dataset.query(f' T1_P0 >= 5 and T2_P0 >= 5  ')
dataset.replace([np.inf, -np.inf], 0, inplace=True)


df_nx, df_ov, df_cn, df_nl = dataset.query(f'NEXT == 1'), dataset.query(f'OVERLAP == 1'), dataset.query(f'CONCURRENT == 1'), dataset.query(f'NULL == 1')


df_nl = df_nl.sample(n = math.floor((len(df_cn) + len(df_nx) + len(df_ov))/3), random_state=2)

print('next = ', len(df_nx))
print('overlap = ', len(df_ov))
print('concurrent = ', len(df_cn))
print('null = ', len(df_nl))


identifiers = ['report', 'T1', 'T2', 'threshold']
labels = ['CONCURRENT', 'NEXT', 'NULL', 'OVERLAP']
feature_names = list(set(dataset.columns) - set(identifiers) - set(labels))


# dataset = pd.concat([df_cn, df_nl, df_nx, df_ov], axis=0)
# dataset = dataset.reset_index()

X = dataset[feature_names].values
y = dataset[labels].values


# y = y.ravel()

# scaler = StandardScaler()
scaler = MinMaxScaler()
X = scaler.fit_transform(X)

print("original shapes: ", X.shape, y.shape)

# with open(f'bagged_classifiers/rfmodel-0.pkl', 'rb') as f:
#     clf : BinaryRelevance = pickle.load(f)
#     probs = clf.predict_proba(X)     
#     predicted_threshold = []
    
#     for prob in probs:
#         predicted_threshold.append(list(prob.toarray()[0]))
       
#     predicted = clf.predict(X)
#     print(classification_report(y, predicted, target_names=labels, zero_division=0))


# print(xxx)

probs_bag = []

for idx in tqdm.tqdm(range(172)):
    with open(f'bagged_classifiers/rfmodel-{idx}.pkl', 'rb') as f:
        clf : BinaryRelevance = pickle.load(f)
        probs = clf.predict_proba(X)
        probs_bag.append(probs)
         
        # predicted = clf.predict(X)
        # print(classification_report(y, predicted, target_names=labels, zero_division=0))
        
        # y_next = [i[1] for i in y]
        
        # y_next_predicted = []
        # for item in probs:
        #     ls = item.toarray()
        #     if ls[0][1] >= 0.25: y_next_predicted.append(1)
        #     else: y_next_predicted.append(0)
        # print(classification_report(y_next, y_next_predicted, zero_division=0))
    

    
with open(f'bagged_classifiers/problist.pkl','wb') as f:
    pickle.dump(probs_bag,f)
    
with open(f'bagged_classifiers/problist.pkl','rb') as f:
    probs_bag = pickle.load(f)


y_next = [i[1] for i in y]
print(sum(y_next))
y_next_predicted = []

for i in tqdm.tqdm(range(probs_bag[0].shape[0])):
    predictions = []
    for probs in probs_bag:
        # for prob in probs:
        #     # print(prob.toarray())
        #     pass
        predictions.append(probs[i].toarray()[0][1])
    predictions.sort(reverse=True)
    # print(statistics.mean(predictions))
    if statistics.median(predictions) >= 0.5: y_next_predicted.append(1)
    else: y_next_predicted.append(0)

print(classification_report(y_next, y_next_predicted, zero_division=0))
pass
    