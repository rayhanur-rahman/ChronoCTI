import json
import math
import pandas as pd
import random
import tqdm
import pickle
import numpy as np
from sklearn.datasets import make_classification
from imblearn.over_sampling import RandomOverSampler
from collections import Counter

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.pipeline import make_pipeline
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import GaussianNB, BernoulliNB
from sklearn.svm import SVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import GradientBoostingClassifier, BaggingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report

from skmultilearn.problem_transform import BinaryRelevance
from sklearn.svm import SVC, OneClassSVM, LinearSVC, NuSVC

import torch
from torch import nn
import torch.nn.functional as F
from skorch import NeuralNetClassifier




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




for prediction_threshold in [5]:

    print(f'threshold = {prediction_threshold}')
    
    file = open('out.txt', 'a')
    
    dataset : pd.DataFrame = pd.read_pickle(f'dataset_df_threshold_{prediction_threshold}.pkl')
    
    # dataset = dataset.head(10000)
    
    identifiers = ['report', 'T1', 'T2', 'threshold']
    labels = ['CONCURRENT', 'NEXT', 'NULL', 'OVERLAP']
    feature_names = list(set(dataset.columns) - set(identifiers) - set(labels))


    X = dataset[feature_names].values
    y = dataset[labels].values

    maxVal = []

    for i in range(len(X)):
        for j in range(len(X[i])):
            if np.isinf(X[i][j]):
                X[i][j] = 0
                
                if len([v for v in maxVal if v[0] == j]) == 0:
                    colVals = []
                    for item in X[i]:
                        colVals.append(item)    
                    
                    colVals = [x for x in colVals if np.isfinite(x)]
                    colVals.sort(reverse=True)
                    
                    maxVal.append((j, colVals[0]))
                
                
                X[i][j] = [v for v in maxVal if v[0] == j][0][1]
                pass


    ros = RandomOverSampler(random_state=0)
    X_resampled, y_resampled = ros.fit_resample(X, y)


    X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, train_size=100000, test_size=20000, random_state=0)

    # models = []
    # models.append(GaussianNB())
    # models.append(BernoulliNB())
    # models.append(DecisionTreeClassifier())
    # models.append(RandomForestClassifier())
    # models.append(BaggingClassifier())
    # models.append(AdaBoostClassifier())
    # models.append(GradientBoostingClassifier())
    # models.append(KNeighborsClassifier())
    # models.append(LinearSVC())
    # models.append(RidgeClassifier())

    # for model in models:
    #     clf = BinaryRelevance(
    #         classifier = model,
    #         # require_dense=[False, True]
    #     )

    #     print(f'threshold: {prediction_threshold} | model: {model} | multi label estimator: {clf} | imbalance resolver: {ros}')
        
    #     file.writelines(f'threshold: {prediction_threshold} | model: {model} | multi label estimator: {clf} | imbalance resolver: {ros}\n')

    #     try:
        
    #         clf = clf.fit(X_train, y_train)
    #         y_predicted = clf.predict(X_test)
    #         file.writelines(f'{classification_report(y_test, y_predicted, target_names=labels, zero_division=0)}\n')
    #     except:
    #         file.writelines(f'failed for some reason \n')

    class MultiClassClassifierModule(nn.Module):
        def __init__(
                self,
                input_dim=X_train.shape[1],
                hidden_dim1=32,
                hidden_dim2=16,
                output_dim=y_train.shape[1],
                dropout=0.2,
        ):
            super(MultiClassClassifierModule, self).__init__()
            self.dropout = nn.Dropout(dropout)

            self.hidden1 = nn.Linear(input_dim, hidden_dim1)
            self.hidden2 = nn.Linear(hidden_dim1, hidden_dim2)
            self.output = nn.Linear(hidden_dim2, output_dim)

        def forward(self, X, **kwargs):
            X = F.relu(self.hidden1(X))
            # X = self.dropout(X)
            X = F.relu(self.hidden2(X))
            X = self.dropout(X)
            X = F.softmax(self.output(X), dim=-1)
            return X
    
    

    model = NeuralNetClassifier(MultiClassClassifierModule, max_epochs=100,verbose=1)
    
    
    
    from skmultilearn.problem_transform import LabelPowerset, ClassifierChain
    clf = BinaryRelevance(classifier=model, require_dense=[True,True])
    # clf = LabelPowerset(classifier=net, require_dense=[True,True])
    # clf = ClassifierChain(classifier=net, require_dense=[False,True])
    
    print(f'threshold: {prediction_threshold} | model: {model} | multi label estimator: {clf} | imbalance resolver: {ros}')
    file.writelines(f'threshold: {prediction_threshold} | model: {model} | multi label estimator: {clf} | imbalance resolver: {ros}\n')
    
    try:
        clf.fit(X_train.astype(np.float32),y_train)
        y_predicted = clf.predict(X_test.astype(np.float32))
        file.writelines(f'{classification_report(y_test, y_predicted, target_names=labels, zero_division=0)}\n')
    except:
        file.writelines(f'failed for some reason \n')

    file.close()



