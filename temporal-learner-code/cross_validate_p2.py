from email import utils
import statistics
from sklearn.model_selection import StratifiedKFold
from sklearn_genetic.plots import plot_fitness_evolution, plot_search_space
from sklearn_genetic.space import Continuous, Categorical, Integer
from sklearn_genetic import GASearchCV
import json
import math
from pydoc import classname
from pyexpat import features
import pandas as pd
import random
import tqdm
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
# if needed. need to be run once.
# Utils.create_dataframe_from_jsons()


selectedTechniques = Utils.get_selected_techniques()
# dataset: pd.DataFrame = Utils.get_dataset_dataframe(threshold=75)
# FEATURE_TYPES = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
# X_train, X_test, y_train, y_test, selected_features, labels, class_weights = Utils.get_train_test_split(dataset, selectedTechniques, methodology = "cross_validation", FEATURE_TYPES=FEATURE_TYPES)

estimators = [TabNetMultiTaskClassifier(verbose=1)]

# passive-aggressive, Ridge, SGD, NearestCentroid, LinearSVC, NUSVC, NuSVC, SVC, RadiusNeighborsClassifier(), IsolationForest, MLPClassifier

thresholds = [95]
feature_types_powerset = list( powerset(['SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']))
feature_types_powerset = [list(x) + ['BASIC'] for x in feature_types_powerset]

feature_types_powerset = [
    ['BASIC'],
    ['BASIC', 'TIME SIGNAL HEURISTIC'],
    ['BASIC', 'TIME SIGNAL HEURISTIC', 'TIMEML'],
    ['BASIC', 'SENTENCE', 'TIMEML', 'TIME SIGNAL HEURISTIC'],
    ['BASIC', 'SENTENCE', 'DISCOURSE', 'TIMEML', 'TIME SIGNAL HEURISTIC'],
    ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
]

for th in thresholds:
    dumps = []
    for feature_set in feature_types_powerset:
        dataset: pd.DataFrame = Utils.get_dataset_dataframe(threshold=th)
        X_train, X_test, y_train, y_test, selected_features, labels, class_weights = Utils.get_train_test_split(dataset, selectedTechniques, methodology = "heldout", FEATURE_TYPES=feature_set, ohe=False)  # type: ignore
        n_splits = 5
        kf = KFold(n_splits=n_splits, shuffle=True, random_state=th)
        
        for estimator in estimators:
            
            dump = {}
            dump['estimator'] = str(estimator)
            dump['threshold'] = int(th)
            dump['feature_set'] = list(feature_set)
            
            dump['precision_macro'] = []
            dump['recall_macro'] = []
            dump['f1_macro'] = []
            
            for i, (train_index, test_index) in enumerate(kf.split(X_train)):
                X_train_split = X_train[train_index]
                y_train_split = y_train[train_index]
                X_test_split = X_train[test_index]
                y_test_split = y_train[test_index]                
                
                clf = TabNetMultiTaskClassifier(verbose=0)
                clf.fit(X_train_split, y_train_split, eval_set=[(X_test_split, y_test_split)])
                y_predicted_array = clf.predict(X_test_split)
                y_predicted_array = np.array(y_predicted_array, dtype=int)
                y_predicted_split = np.transpose(y_predicted_array) 

                dump['precision_macro'].append(precision_score(y_test_split, y_predicted_split, average='macro', zero_division=0))
                dump['recall_macro'].append(recall_score(y_test_split, y_predicted_split, average='macro', zero_division=0))
                dump['f1_macro'].append(f1_score(y_test_split, y_predicted_split, average='macro', zero_division=0))

            dumps.append(dump)
            mean, median, stdev = statistics.mean(dump['f1_macro']), statistics.median(dump['f1_macro']), statistics.stdev(dump['f1_macro'])
            print(f'{str(type(estimator))} || {th} || {feature_set} <==> {median}')                 
        
        print('')
        
    json.dump(dumps, open(f'cross_validation/cross_validation_{th}_TABNET_without_ohe.json', 'w'))
    print('')