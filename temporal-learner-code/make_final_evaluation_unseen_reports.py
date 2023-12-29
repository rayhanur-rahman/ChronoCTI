from email import utils
import statistics
from sklearn.model_selection import StratifiedKFold
from sklearn_genetic.plots import plot_fitness_evolution, plot_search_space
from sklearn_genetic.space import Continuous, Categorical, Integer
from sklearn_genetic import GASearchCV
import json
import math
from pydoc import classname
from sklearn_genetic import GAFeatureSelectionCV
from pyexpat import features
import pandas as pd
import random
from sklearn_genetic import GASearchCV
from sklearn_genetic.space import Categorical, Integer, Continuous
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.neural_network import MLPClassifier
from sklearn.datasets import load_digits
from sklearn.metrics import accuracy_score
import tqdm
from collections import Counter
from sklearn.datasets import make_classification
from imblearn.over_sampling import *
from imblearn.under_sampling import *
from imblearn.combine import *
import pickle
import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.datasets import make_classification
from imblearn.over_sampling import RandomOverSampler
from collections import Counter
from imblearn.over_sampling import SMOTE, ADASYN
from imblearn.combine import SMOTETomek
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.linear_model import *
from sklearn.pipeline import make_pipeline
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import *
from sklearn.svm import *
from sklearn.tree import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import *
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import GradientBoostingClassifier, BaggingClassifier
from sklearn.neighbors import *
from sklearn.metrics import accuracy_score, classification_report
from skmultilearn.problem_transform import BinaryRelevance
from sklearn.svm import SVC
import torch
from torch import nn
import torch.nn.functional as F
from skorch import NeuralNetClassifier
from imblearn.ensemble import BalancedBaggingClassifier
from imblearn.ensemble import BalancedRandomForestClassifier, RUSBoostClassifier
from sklearn.datasets import load_digits
from sklearn.feature_selection import SelectKBest, chi2, f_classif
import shap
import pandas as pd
import numpy as np
from imblearn.ensemble import EasyEnsembleClassifier
import Utils
from skmultilearn.adapt import BRkNNaClassifier
from sklearn.naive_bayes import GaussianNB
from skmultilearn.ensemble import RakelD
from skmultilearn.adapt import MLkNN
from sklearn.model_selection import GridSearchCV
from sklearn.multioutput import MultiOutputClassifier
from pytorch_tabnet.multitask import TabNetMultiTaskClassifier
import networkx as nx
from more_itertools import powerset
from sklearn.ensemble import *
from sklearn.metrics import *
from sklearn.model_selection import *
import xgboost as xgb
import tabulate
# if needed. need to be run once.
# Utils.create_dataframe_from_jsons()

selectedTechniques = Utils.get_selected_techniques()
dataset: pd.DataFrame = Utils.get_dataset_dataframe()

dataset.drop('BEGUN_BY_TIMEML', axis=1, inplace=True)
print(dataset.shape)

clf = None

with open('saved_xgb_model.pkl', 'rb') as f:
    clf = pickle.load(f)

FEATURE_TYPES = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
X_train, X_test, y_train, y_test, selected_features, labels, class_weights, reports, ttp_pairs = Utils.get_train_test_split(dataset, selectedTechniques, methodology = "test", ohe=True) # type: ignore

print(X_train.shape)

y_predicted = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)
y_prob_transposed = Utils.transpose_multiTaskOutput_to_predict_prob(clf.predict_proba(X_test))

concurrent_list = []
next_list = []
overlap_list = []

for idx in range(len(y_prob_transposed)):
    vector = y_prob_transposed[idx]
    te1 = ttp_pairs[idx][0]
    te1 = [x for x in selectedTechniques if x['id'] == te1][0]
    te2 = ttp_pairs[idx][1]
    te2 = [x for x in selectedTechniques if x['id'] == te2][0]
    
    pair = (f'{te1["title"]}', f'{te2["title"]}')
    report = reports[idx]
    
    if vector[0] >= 0.5:
        concurrent_list.append({
            'pair': pair,
            'report': report
        })
    
    if vector[1] >= 0.5:
        next_list.append({
            'pair': pair,
            'report': report
        })
        
    if vector[3] >= 0.5:
        overlap_list.append({
            'pair': pair,
            'report': report
        })


temporal_patterns_data = []

for item in concurrent_list:
    ls = list(item['pair'])
    ls.sort()
    pattern = ' || '.join(ls)
    
    if len([p for p in temporal_patterns_data if p['pattern'] == pattern and p['type'] == 'concurrent' and p['source'] == item['report'] ]) > 0:
        continue
    
    temporal_patterns_data.append(
        {
            'pattern': pattern,
            'type': 'concurrent',
            'source': item['report']
        }
    )

for item in overlap_list:
    ls = list(item['pair'])
    ls.sort()
    pattern = ' ++ '.join(ls)
    
    if len([p for p in temporal_patterns_data if p['pattern'] == pattern and p['type'] == 'overlap' and p['source'] == item['report'] ]) > 0:
        continue
    
    temporal_patterns_data.append(
        {
            'pattern': pattern,
            'type': 'overlap',
            'source': item['report']
        }
    )

for item in next_list:
    ls = list(item['pair'])
    pattern = ' >> '.join(ls)
    
    if len([p for p in temporal_patterns_data if p['pattern'] == pattern and p['type'] == 'next' and p['source'] == item['report'] ]) > 0:
        continue
    
    temporal_patterns_data.append(
        {
            'pattern': pattern,
            'type': 'next',
            'source': item['report']
        }
    )


pattern_df = pd.DataFrame.from_dict(temporal_patterns_data)

pattern_types = [x['type'] for x in temporal_patterns_data]
print(Counter(pattern_types))

pattern_df.to_excel('patterns_detailed_v2.xlsx')

pattern_dfg = pattern_df.groupby('pattern')['pattern'].count().sort_values(ascending=False)
pattern_dfg.to_excel('patterns_v2.xlsx')


# concurrent_list_counter = Counter(concurrent_list)
# next_list_counter = Counter(next_list)
# overlap_list_counter = Counter(overlap_list)


pass



