import json
import math
from pydoc import classname
from pyexpat import features
import pandas as pd
import random
import tqdm
import pickle
import numpy as np
from sklearn.datasets import make_classification
from imblearn.over_sampling import RandomOverSampler
from collections import Counter
from imblearn.over_sampling import SMOTE, ADASYN
from imblearn.combine import SMOTETomek
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.pipeline import make_pipeline
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC, OneClassSVM
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
from imblearn.ensemble import BalancedBaggingClassifier
from imblearn.ensemble import BalancedRandomForestClassifier, RUSBoostClassifier
from sklearn.datasets import load_digits
from sklearn.feature_selection import SelectKBest, chi2, f_classif
import shap
import pandas as pd
import numpy as np
import networkx as nx
import dgl.nn
import dgl.data
import dgl
import networkx as nx
import os
from email import utils
import statistics
from sklearn.model_selection import StratifiedKFold
from sklearn_genetic.plots import plot_fitness_evolution, plot_search_space
from sklearn_genetic.space import Continuous, Categorical, Integer
from sklearn_genetic import GASearchCV
import json, tabulate
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
# if needed. need to be run once.
# Utils.create_dataframe_from_jsons()
from torch.autograd import Variable
import torchmetrics
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.utils import class_weight
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import roc_curve, auc
import shap
from sklearn.feature_selection import SelectKBest, chi2, f_classif
from sklearn.datasets import load_digits
from imblearn.ensemble import BalancedRandomForestClassifier, RUSBoostClassifier
from imblearn.ensemble import BalancedBaggingClassifier
from skorch import NeuralNetClassifier
from torch import nn
import torch
from sklearn.svm import SVC
from skmultilearn.problem_transform import BinaryRelevance
from sklearn.metrics import accuracy_score, classification_report
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import GradientBoostingClassifier, BaggingClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC, OneClassSVM
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
from sklearn.datasets import load_iris
from sklearn.pipeline import make_pipeline
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn import metrics
from imblearn.combine import SMOTETomek
from imblearn.over_sampling import SMOTE, ADASYN
from collections import Counter
from imblearn.over_sampling import RandomOverSampler
from sklearn.datasets import make_classification
from pyexpat import features
from pydoc import classname
import torch.nn.functional as F
import torch.nn as nn
import dgl.nn as dglnn
import json
import math
from operator import ne
import pandas as pd
import random
import tqdm
import pickle
import numpy as np
from pyprobs import Probability as pr
import dgl.function as fn
import matplotlib.pyplot as plt
import dgl.function as fn

from imblearn.ensemble import EasyEnsembleClassifier

from sklearn.metrics import *

def create_dataframe_from_jsons():
    for prediction_threshold in range(95, 90, -5):
        print(f'prediction_threshold == {prediction_threshold}')
        
        # PATH_TO_JSON_FILE = 'unseen_reports_features/all_reports_threshold_95.json'        
        # PATH_TO_DATAFRAME_FILE = 'unseen_reports_features/dataset_df_threshold_95.pkl' 
        
        PATH_TO_JSON_FILE = 'temporal_features_v2/all_reports_threshold_95_v3.json'
        PATH_TO_DATAFRAME_FILE = 'saved_features_dataframes/dataset_df_threshold_95_v3.pkl'
        
        # PATH_TO_JSON_FILE = 'temporal_features_v2/all_reports_threshold_95_v3.json'
        # PATH_TO_DATAFRAME_FILE = 'saved_features_dataframes/dataset_df_threshold_95_v3_combined.pkl'
        
        # PATH_TO_TEMPORAL_RELATION_DATASET = f'temporal_relation_dataset_combined.xlsx' 
        PATH_TO_TEMPORAL_RELATION_DATASET = 'temporal_relation_dataset.xlsx'
        
        dataset = json.load( open(f'{PATH_TO_JSON_FILE}') )
        random.shuffle(dataset)

        df_labels = pd.read_excel(f'{PATH_TO_TEMPORAL_RELATION_DATASET}')

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

        dataset_df.to_pickle(f"{PATH_TO_DATAFRAME_FILE}")

        print(dataset_df.shape)
        # print(dataset_df.head())
        print('next = ', len(dataset_df.query(f'NEXT == 1')))
        print('overlap = ', len(dataset_df.query(f'OVERLAP == 1')))
        print('concurrent = ', len(dataset_df.query(f'CONCURRENT == 1')))
        print('null = ', len(dataset_df.query(f'NULL == 1')))
        print('')


def get_train_test_reports():
    # df_temporal = pd.read_excel('temporal_relation_dataset.xlsx')
    df_temporal = pd.read_excel('temporal_relation_dataset_combined.xlsx')

    train_reports = list(set(df_temporal.query(
        ' mask == "train" ')['report'].tolist()))
    eval_reports = list(set(df_temporal.query(
        ' mask == "eval" ')['report'].tolist()))

    return train_reports, eval_reports


def get_selected_techniques():
    selectedTechniques = []
    file = open('selected_techniquesWName.json', 'r')
    selectedTechniques = json.load(file)
    return selectedTechniques


def get_dataset_dataframe(threshold=95) -> pd.DataFrame:
    PATH_TO_DATAFRAME_FILE = 'unseen_reports_features/dataset_df_threshold_95.pkl'
    # PATH_TO_DATAFRAME_FILE = f'saved_features_dataframes/dataset_df_threshold_{threshold}_v3.pkl'
    # PATH_TO_DATAFRAME_FILE = f'saved_features_dataframes/dataset_df_threshold_95_v3_combined.pkl'
    
    dataset: pd.DataFrame = pd.read_pickle(f'{PATH_TO_DATAFRAME_FILE}')
    return dataset


def transform_dataset_tabular_learning(dataset_input : pd.DataFrame, selectedTechniques, DATASET_THRESHOLD=0.95, FEATURE_SELECTION=False, FEATURE_TYPES = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC'], ohe=True):
    
    features_df = pd.read_excel('Features.xlsx', sheet_name='features')

    feature_types = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
    feature_dict = {}
    for item in feature_types:
        feature_dict[f'{item}'] = []

    for idx, row in features_df.iterrows():
        for item in feature_types:
            if row['Type'] == item:
                feature_dict[f'{item}'].append(row['Feature'])
    
    dataset = dataset_input
    dataset['Te1'] = dataset['T1']
    dataset['Te2'] = dataset['T2']
    dataset = pd.get_dummies(dataset, columns=['T1', 'T2'])

    ohe_feature_names = []

    for te in selectedTechniques:
        dataset[f"T1_{te['id']}"] = dataset[f"T1_{te['id']}"].astype(int)
        dataset[f"T2_{te['id']}"] = dataset[f"T2_{te['id']}"].astype(int)
        ohe_feature_names.append(f"T1_{te['id']}")
        ohe_feature_names.append(f"T2_{te['id']}")

    datasetq1 = dataset.query(
        f'T1_P0 >= {DATASET_THRESHOLD} and T2_P0 >= {DATASET_THRESHOLD}')
    datasetq2 = dataset.query(
        f'(T1_P0 < {DATASET_THRESHOLD} and T2_P0 < {DATASET_THRESHOLD}) and (NEXT == 1 or OVERLAP == 1 or CONCURRENT == 1)')
    dataset = pd.concat([datasetq1, datasetq2], ignore_index=True)

    identifiers = ['report', 'T1', 'T2', 'threshold', 'Te1', 'Te2']
    labels = ['CONCURRENT', 'NEXT', 'NULL', 'OVERLAP']
    feature_names = list(set(dataset.columns) - set(identifiers) -
                         set(labels) - set(ohe_feature_names))

    selected_features = ['ELABORATION_NEXT',
                         'same_sentence',
                         'AFTER_TIMEML',
                         'BEFORE_TIMEML',
                         'consecutive_sentence_n4',
                         'SIMULTANEOUS_TIMEML',
                         'phi_AMR',
                         'DURING_TIMEML',
                         'INCLUDES_TIMEML',
                         'consecutive_sentence_p3',
                         'same_coreference_cluster',
                         'consecutive_sentence_p5',
                         'similarity',
                         'pmi_AMR', 'xy_AMR', 'supportXY_AMR', 'MISC_NEXT', 'IDENTITY_TIMEML', 'jaccard_AMR', 'MISC_COREF', 'supportY_AMR', 'confidence_AMR', 'nxny_AMR',
                         'consecutive_sentence_n3',
                         'consecutive_sentence_p4',
                         'consecutive_sentence_p1',
                         'consecutive_sentence_n2',
                         'ELABORATION_COREF',
                         'consecutive_sentence_n5',
                         'NEXT_COREF',
                         'consecutive_sentence_p2',
                         'consecutive_sentence_n1',
                         'NEXT_NEXT',
                         'T1_P0', 'T1_P1', 'T1_P2', 'T1_P3', 'T1_P4',
                         'T2_P0', 'T2_P1', 'T2_P2', 'T2_P3', 'T2_P4'
                         ]

    if not FEATURE_SELECTION:
        selected_features = feature_names

    selected_features = []
    for item in FEATURE_TYPES:
        for key in feature_dict.keys():
            if key == item:
                selected_features.extend(feature_dict[key])
    
    # print(len(selected_features))
    # print(len(ohe_feature_names))
    # print(xxx)
    
    # selected_features = []
    if ohe: selected_features = list(selected_features) + list(ohe_feature_names)
    else: selected_features = list(selected_features)
    
    dataset.replace([np.inf, -np.inf], 0, inplace=True)

    for item in feature_names:
        dataset[item] = MinMaxScaler().fit_transform(
            np.array(dataset[item]).reshape(-1, 1))

    class_weights = []

    try:
        for label in labels:
            dfq = dataset.query(f' {label} == 1 ')
            class_weights.append(len(dataset) / (len(labels) * len(dfq)))

    except:
        pass

    
    list_ttp_pairs = []
    
    for idx, row in dataset.iterrows():
        list_ttp_pairs.append((row['Te1'], row['Te2']))
        
    X = dataset[selected_features].values
    y = dataset[labels].values

    return X, y, selected_features, labels, class_weights, dataset['report'].tolist(), list_ttp_pairs


def get_train_test_dataset_dataframe(dataset, train_reports, test_reports):
    train_dataset = dataset.query(f' report in {train_reports} ')
    test_dataset = dataset.query(f' report in {test_reports} ')
    return train_dataset, test_dataset

def get_report_dataframe(dataset, selectedTechniques, FEATURE_TYPES):
    _, test_reports = get_train_test_reports()
    
    list_X_test, list_y_test, list_report_ids, list_ttp_pairs = [], [], [], []
    
    # print(dataset.columns)
    
    for report in test_reports:
        report_dataset = dataset.query(f' report == "{report}" ')
        X_test, y_test, _, _, _, report_ids, ttp_pairs = transform_dataset_tabular_learning(report_dataset, selectedTechniques, FEATURE_TYPES=FEATURE_TYPES)    
        list_X_test.append(X_test)
        list_y_test.append(y_test)
        list_report_ids.append(report_ids[0])
        list_ttp_pairs.append(ttp_pairs)
        
    return list_X_test, list_y_test, list_report_ids, list_ttp_pairs

def get_report_graph(dataset):
    _, test_reports = get_train_test_reports()
    
    graphs = []
    
    for report in test_reports:
        report_dataset : pd.DataFrame = dataset.query(f' report == "{report}" ')
        graph : nx.Graph = nx.DiGraph()
        
        for idx, row in report_dataset.iterrows():                
            if row["NULL"] == 0:
                
                if not graph.has_node(row['T1']):
                    graph.add_node(row['T1'], label = row['T1'])
                
                if not graph.has_node(row['T2']):
                    graph.add_node(row['T2'], label = row['T2'])
                
                if row['CONCURRENT'] == 1:
                    graph.add_edge(row["T1"], row["T2"], edgeType = "CONCURRENT", src=row['T1'], dst=row['T2'])
                if row['NEXT'] == 1:
                    graph.add_edge(row["T1"], row["T2"], edgeType = "NEXT", src=row['T1'], dst=row['T2'])
                if row['OVERLAP'] == 1:
                    graph.add_edge(row["T1"], row["T2"], edgeType = "OVERLAP", src=row['T1'], dst=row['T2'])        
        graphs.append(graph)
    
    return graphs
    

def get_report_graph_predicted(y_predicted, ttp_pairs):
    
    
    graph = nx.DiGraph()
    
    for idx in range(len(ttp_pairs)):
        pair = ttp_pairs[idx]
        prediction = y_predicted[idx]
        
        if prediction[2] == 0:
            
            if not graph.has_node(pair[0]):
                graph.add_node(pair[0], label = pair[0])
                
            if not graph.has_node(pair[1]):
                graph.add_node(pair[1], label = pair[1])
            
            if prediction[0] == 1:
                graph.add_edge(pair[0], pair[1], edgeType = 'CONCURRENT', src=pair[0], dst=pair[1])
            if prediction[1] == 1:
                graph.add_edge(pair[0], pair[1], edgeType = 'NEXT', src=pair[0], dst=pair[1])
            if prediction[3] == 1:
                graph.add_edge(pair[0], pair[1], edgeType = 'OVERLAP', src=pair[0], dst=pair[1])
    
    nx.write_gml(graph, 'test.gml')
    return graph
    
def get_train_test_split(dataset, selectedTechniques, DATASET_THRESHOLD=0.95, methodology = 'cross_validation', FEATURE_TYPES = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC'], ohe=True):
    
    if methodology == 'test':
        X, y, selected_features, labels, class_weights, reports, ttp_pairs = transform_dataset_tabular_learning(
        dataset, selectedTechniques, DATASET_THRESHOLD=DATASET_THRESHOLD, FEATURE_TYPES=FEATURE_TYPES, ohe=ohe)
        return X, X, y, y, selected_features, labels, class_weights, reports, ttp_pairs
    
    if methodology == 'cross_validation':
        X, y, selected_features, labels, class_weights, reports, ttp_pairs = transform_dataset_tabular_learning(
        dataset, selectedTechniques, DATASET_THRESHOLD=DATASET_THRESHOLD, FEATURE_TYPES=FEATURE_TYPES, ohe=ohe)
        X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=0)
        return X_train, X_test, y_train, y_test, selected_features, labels, class_weights, reports, ttp_pairs
    
    if methodology == 'heldout':
        train_reports, test_reports = get_train_test_reports()
        train_dataset, test_dataset = get_train_test_dataset_dataframe(
            dataset, train_reports, test_reports)
        X_train, y_train, selected_features, labels, class_weights, reports, ttp_pairs = transform_dataset_tabular_learning(
            train_dataset, selectedTechniques,DATASET_THRESHOLD=DATASET_THRESHOLD, FEATURE_TYPES=FEATURE_TYPES, ohe=ohe)
        X_test, y_test, _, _, _, _, _ = transform_dataset_tabular_learning(
            test_dataset, selectedTechniques,DATASET_THRESHOLD=DATASET_THRESHOLD, FEATURE_TYPES=FEATURE_TYPES, ohe=ohe)
        return X_train, X_test, y_train, y_test, selected_features, labels, class_weights, reports, ttp_pairs

def convert_to_tensors(X_train, y_train, X_test, y_test):
    X_train_out = torch.tensor(X_train, dtype=torch.float64)
    y_train_out = torch.tensor(y_train, dtype=torch.float64)
    
    X_test_out = torch.tensor(X_test, dtype=torch.float64)
    y_test_out = torch.tensor(y_test, dtype=torch.float64)
    
    return X_train_out, y_train_out, X_test_out, y_test_out


def get_y_prob(y_prob_in):
    y_prob_transformed = []
    for row in y_prob_in:
        ls = []
        for column in row:
            ls.append(column[1])
        y_prob_transformed.append(ls)

    y_prob = np.array(y_prob_transformed, dtype=float)
    y_prob = np.transpose(y_prob)
    return y_prob

def compute_hits_k(y_test, y_prob, POS, K = 100):
    label_probs = []
    for prob, truth in zip(y_prob, y_test):
        label_prob = prob[POS]
        label_pred = truth[POS]
        label_probs.append((label_prob, label_pred))

    label_probs.sort(key=lambda v: v[0], reverse=True)

    HITS = 0

    for item in label_probs[:K]:
        if item[1] == 1 and item[0] > 0.5:
            HITS += 1

    return HITS / K


def compute_prec_k(y_test, y_prob, POS, K = 100):
    label_probs = []
    for prob, truth in zip(y_prob, y_test):
        label_prob = prob[POS]
        label_pred = truth[POS]
        label_probs.append((label_prob, label_pred))

    label_probs.sort(key=lambda v: v[0], reverse=True)
    
    TP, FP = 0, 0

    for item in label_probs[:K]:
        if item[1] == 1 and item[0] > 0.5:
            TP += 1
        if item[1] == 0 and item[0] > 0.5:
            FP += 1
    try:
        return (TP/(TP+FP))
    except:
        return 0

def compute_rec_k(y_test, y_prob, POS, K = 100):
    label_probs = []
    for prob, truth in zip(y_prob, y_test):
        label_prob = prob[POS]
        label_pred = truth[POS]
        label_probs.append((label_prob, label_pred))

    label_probs.sort(key=lambda v: v[0], reverse=True)
    
    TP, FN = 0, 0

    for item in label_probs[:K]:
        if item[1] == 1 and item[0] > 0.5:
            TP += 1
        if item[1] == 1 and item[0] <= 0.5:
            FN += 1

    try: 
        return (TP/(TP+FN))
    except:
        return 0

def get_confusion_matrix(y_test, y_predicted, POS):
    y_test_labels = y_test[:, POS]
    y_predicted_labels = y_predicted[:, POS]
    TN, FP, FN, TP =  confusion_matrix(y_test_labels, y_predicted_labels).ravel()
    return TP, TN, FP, FN

def get_true_negative_rate(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return TN/(TN+FP)

def get_false_negative_rate(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return FN/(FN+TP)

def get_false_positive_rate(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return FP/(FP+TN)

def get_negative_predictive_value(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return TN/(TN+FN)

def get_false_discovery_rate(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return FP/(FP+TP)

def get_false_omission_rate(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return FN/(FN+TN)

def get_positive_likelihood_ratio(y_test, y_predicted, POS):
    return (1 - get_false_negative_rate(y_test, y_predicted, POS)) / get_false_positive_rate(y_test, y_predicted, POS)

def get_negative_likelihood_ratio(y_test, y_predicted, POS):
    return get_false_negative_rate(y_test, y_predicted, POS) / get_true_negative_rate(y_test, y_predicted, POS)

def get_prevalence_threshold(y_test, y_predicted, POS):
    return math.sqrt(get_false_positive_rate(y_test, y_predicted, POS)) / ( math.sqrt(get_false_positive_rate(y_test, y_predicted, POS)) + math.sqrt(1 - get_false_negative_rate(y_test, y_predicted, POS)) )

def get_threat_score(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return TP / (TP + FN + FP)

def get_balanced_accuracy(y_test, y_predicted, POS):
    TN, FP, FN, TP =  get_confusion_matrix(y_test, y_predicted, POS)
    return ( (1 - get_false_negative_rate(y_test, y_predicted, POS)) + get_true_negative_rate(y_test, y_predicted, POS)) / 2

def nmatch(n1, n2):
    return n1['label'] == n2['label']

def ematch(e1, e2):
    return e1['src'] == e2['src'] and e1['dst'] == e2['dst']
    return e1['src'] == e2['src'] and e1['dst'] == e2['dst'] and e1['edgeType'] == e2['edgeType']

def compute_MUC(dataset, selectedTechniques, clf, FEATURE_TYPES):

    list_X_test, list_y_test, list_report_ids, list_ttp_pairs = get_report_dataframe(dataset, selectedTechniques, FEATURE_TYPES=FEATURE_TYPES)
    graph_test = get_report_graph(dataset)

    for idx in range(len(list_X_test)):
        y_predicted = clf.predict(list_X_test[idx])
        graph_predicted = get_report_graph_predicted(y_predicted, list_ttp_pairs[idx])
        print(nx.graph_edit_distance(graph_predicted, graph_test[idx], node_match=nmatch, edge_match=ematch))


        CORRECT, PARTIAL, MISSING, SPURIOUS = 0, 0, 0, 0
        
        for pEdge in graph_predicted.edges():
            peData = graph_predicted.edges[pEdge[0], pEdge[1]]

            IS_SPURIOUS = True
            
            for edge in graph_test[idx].edges():
                eData = graph_test[idx].edges[edge[0], edge[1]]
                
                if eData['src'] == peData['src'] and eData['dst'] == peData['dst']:
                    CORRECT += 1
                    IS_SPURIOUS = False
                    break
                
                if (eData['src'] == peData['src'] or eData['dst'] == peData['dst']) and not ((eData['src'] == peData['src'] and eData['dst'] == peData['dst'])):
                    PARTIAL += 1
                    IS_SPURIOUS = False
                    break
            
            if IS_SPURIOUS: 
                SPURIOUS += 1
            
        for edge in graph_test[idx].edges():
            eData = graph_test[idx].edges[edge[0], edge[1]]
            
            IS_MISSING = True
            
            for pEdge in graph_predicted.edges():
                peData = graph_predicted.edges[pEdge[0], pEdge[1]]
                
                if eData['src'] == peData['src'] and eData['dst'] == peData['dst']:
                    IS_MISSING = False
                    break
            
            if IS_MISSING: 
                MISSING += 1
        
        MUC_PREC = (CORRECT + 0.5 * PARTIAL) / (CORRECT + SPURIOUS + PARTIAL + 1e-10)
        MUC_REC = (CORRECT + 0.5 * PARTIAL) / (CORRECT + MISSING + PARTIAL + 1e-10)
        MUC_F1 = 2 * (MUC_PREC * MUC_REC) / (MUC_PREC + MUC_REC + 1e-10)
        
        print(f'{MUC_PREC} - {MUC_REC} - {MUC_F1}\n')
                                                                        
def transpose_multiTaskOutput_to_predict_prob(y_prob):
    array_2d = []
    for idx in range(len(y_prob)):
        array_1d = []
        array = y_prob[idx]
        for item in array:
            array_1d.append(item[1])
        array_2d.append(array_1d)
    y_prob = np.transpose(array_2d)
    return y_prob   

def perform_cross_validation():
    
    estimators = [RandomForestClassifier(), AdaBoostClassifier(), BaggingClassifier(), ExtraTreesClassifier(), GradientBoostingClassifier(), HistGradientBoostingClassifier(), MultinomialNB(), BernoulliNB(), GaussianNB(), KNeighborsClassifier(),  DecisionTreeClassifier(), ExtraTreeClassifier(), xgb.XGBClassifier(), MLPClassifier(max_iter=1000, verbose=False, early_stopping=True), PassiveAggressiveClassifier(), RidgeClassifier(), SGDClassifier(), NearestCentroid()]
    
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
    
    scoring = {
    'precision_macro': make_scorer(precision_score, average='macro', zero_division=0),
    'recall_macro': make_scorer(recall_score, average='macro', zero_division=0),
    'f1_macro': make_scorer(f1_score, average='macro', zero_division=0),
    
    # 'precision_micro': make_scorer(precision_score, average='micro', zero_division=0),
    # 'recall_micro': make_scorer(recall_score, average='micro', zero_division=0),
    # 'f1_micro': make_scorer(f1_score, average='micro', zero_division=0),
    
    # 'precision_weighted': make_scorer(precision_score, average='weighted', zero_division=0),
    # 'recall_weighted': make_scorer(recall_score, average='weighted', zero_division=0),
    # 'f1_weighted': make_scorer(f1_score, average='weighted', zero_division=0),
    
    # 'precision_samples': make_scorer(precision_score, average='samples', zero_division=0),
    # 'recall_samples': make_scorer(recall_score, average='samples', zero_division=0),
    # 'f1_samples': make_scorer(f1_score, average='samples', zero_division=0),
    
    # 'fbeta_precision': make_scorer(fbeta_score, average='macro', beta=0.5),
    # 'fbeta_rec': make_scorer(fbeta_score, average='macro', beta=2),
    
    # 'accuracy': 'accuracy',
    # 'roc_auc': make_scorer(roc_auc_score, average='macro'),
    
    # 'avg_precision': make_scorer(average_precision_score, needs_proba=True),
    # 'hamming_loss': make_scorer(hamming_loss),
    # # 'log_loss': make_scorer(log_loss),
    # 'jaccard_score': make_scorer(jaccard_score, average='macro'),
    
    # 'dcg': make_scorer(dcg_score, k = 100),
    # 'ndcg': make_scorer(ndcg_score, k =100),
    
    # 'coverage_error': make_scorer(coverage_error),
    # 'label_ranking_avg_precision_score': make_scorer(label_ranking_average_precision_score),
    # 'label_ranking_loss': make_scorer(label_ranking_loss),
    
    
    # 'prec@k@next': make_scorer(Utils.compute_prec_k, needs_proba=True, POS=1),
    # 'prec@k@overlap': make_scorer(Utils.compute_prec_k, needs_proba=True, POS=3),
    # 'prec@k@concurrent': make_scorer(Utils.compute_prec_k, needs_proba=True, POS=0),
    
    # 'rec@k@next': make_scorer(Utils.compute_rec_k, needs_proba=True, POS=1),
    # 'rec@k@overlap': make_scorer(Utils.compute_rec_k, needs_proba=True, POS=3),
    # 'rec@k@concurrent': make_scorer(Utils.compute_rec_k, needs_proba=True, POS=0)
    }   
    metrics = scoring.keys()
    for th in thresholds:
        dumps = []
        for feature_set in feature_types_powerset:
            dataset: pd.DataFrame = Utils.get_dataset_dataframe(threshold=th)
            X_train, X_test, y_train, y_test, selected_features, labels, class_weights, reports, ttp_pairs = Utils.get_train_test_split(dataset, selectedTechniques, methodology = "heldout", FEATURE_TYPES=feature_set, ohe=False)  # type: ignore
            print("k-fold shape: ", X_train.shape)
            n_splits = 5
            kf = KFold(n_splits=n_splits, shuffle=True, random_state=th)
            for estimator in estimators:
                # try:               
                clf = MultiOutputClassifier(estimator)
                scores = cross_validate(clf, X_train, y_train, cv=kf, scoring=scoring)
                dump = {}
                dump['estimator'] = str(estimator)
                dump['threshold'] = int(th)
                dump['feature_set'] = list(feature_set)
                for key in scores.keys():
                    dump[key] = []
                    for item in list(scores[key]):
                        dump[key].append(float(item))
                dumps.append(dump)
                mean, median, stdev = statistics.mean(dump['test_f1_macro']), statistics.median(dump['test_f1_macro']), statistics.stdev(dump['test_f1_macro'])
                print(f'{str(type(estimator))} || {th} || {feature_set} <==> {median}')                 
                # except:
                #     print(f'{estimator} || {th} || {feature_set} Failed')
            
            print('')
            
        json.dump(dumps, open(f'cross_validation/cross_validation_{th}_without_ohe.json', 'w'))
        print('')
                                                                          


def hyperParamOptimization():
    from sklearn.model_selection import GridSearchCV
    param_grid = {
        'max_depth': [3, 7, 11],
        'learning_rate': [0.2, 0.1, 0.01, 0.001],
        'subsample': [0.25, 0.5, 0.75, 1],
        'n_estimators': [50, 100, 200, 400],
        'colsample_bytree': [0.25, 0.5, 0.75, 1],
        # 'gamma': [0],
        # 'lambda': [1],
        # 'alpha': [0],
        'min_child_weight': [0.5, 1, 2, 4]
    }
    clf = xgb.XGBClassifier(device='gpu')
    grid_search = GridSearchCV(clf, param_grid, cv=5, scoring='f1_macro', verbose=3)
    grid_search.fit(X_train, y_train)
    print("Best set of hyperparameters: ", grid_search.best_params_)
    print("Best score: ", grid_search.best_score_)
    return

def hyperParamOptimizationGenetic():
    
    param_grid = {
        'max_depth': Integer(3, 11),
        'learning_rate': Categorical([0.4, 0.3, 0.2, 0.1, 0.01, 0.001]),
        'subsample': Continuous(0.25, 1),
        'n_estimators': Categorical([50, 100, 200, 400]),
        'colsample_bytree': Continuous(0.25, 1),
        'min_child_weight': Continuous(0.25, 4),
        'max_delta_step': Integer(1, 10)
    }
    cv = KFold(shuffle=True)
    clf = xgb.XGBClassifier(device='gpu')
    evolved_estimator = GASearchCV(estimator=clf,
                              cv=cv,
                              scoring='f1_macro',
                              param_grid=param_grid,
                              n_jobs=-1,
                              verbose=True,
                              population_size=10,
                              generations=20)
    evolved_estimator.fit(X_train, y_train)
    print(evolved_estimator.best_params_)
    return

def FeatureSelectionGenetic():
    clf = xgb.XGBClassifier(device='gpu')
    
    evolved_estimator = GAFeatureSelectionCV(
    estimator=clf,
    cv=3,
    scoring="f1_macro",
    population_size=30,
    generations=20,
    n_jobs=-1,
    verbose=True,
    keep_top_k=2,
    elitism=True,
    )
    
    evolved_estimator.fit(X_train, y_train)
    features = evolved_estimator.support_

    f = open('feature_vecs.txt', 'w')
    f.write(f"{features}")
    f.close()
    
    y_predict_ga = evolved_estimator.predict(X_test)
    accuracy = f1_score(y_test, y_predict_ga, average='macro', zero_division=0)
    return



def class_imbalance_handling(X_train, y_train, X_test, y_test):
## Sampling SMOTE ADASYN SVMSMOTE KMeansSMOTE(cluster_balance_threshold=0.01)
    balancers = [ClusterCentroids(), CondensedNearestNeighbour(), EditedNearestNeighbours(), RepeatedEditedNearestNeighbours(), AllKNN(), InstanceHardnessThreshold(), NearMiss(), NeighbourhoodCleaningRule(), OneSidedSelection(), RandomUnderSampler(), TomekLinks(), SMOTE(), ADASYN(), BorderlineSMOTE(), SVMSMOTE(), KMeansSMOTE(cluster_balance_threshold=0.01), SMOTEENN(), SMOTETomek()]
    
    # balancers = [KMeansSMOTE(cluster_balance_threshold=0.01, k_neighbors=2)]

    for sm in balancers:
        try:
            X_train_res, y_train_res = sm.fit_resample(X_train, y_train)  # type: ignore
            clf = MultiOutputClassifier(xgb.XGBClassifier())
            clf = clf.fit(X_train_res, y_train_res)
            y_predicted = clf.predict(X_test)
            macro_precision = precision_score(y_test, y_predicted, average='macro', zero_division=0)
            macro_recall = recall_score(y_test, y_predicted, average='macro', zero_division=0)
            macro_f1 = f1_score(y_test, y_predicted, average='macro', zero_division=0)
            print(f'{type(sm)} >> P: {round(macro_precision, 2)} | R: {round(macro_recall, 2)} | F: {round(macro_f1, 2)}')
        except:
            print(f'{type(sm)} >> FAILED')

    input('EOF...')

def get_y_predicted_threshold(y_prob, threshold = 0.5):
    y_predicted_threshold = []

    for idx in range(len(y_prob)):
        row = y_prob[idx]
        row_output = []
        for item in row: 
            if item >= threshold: row_output.append(1)
            else: row_output.append(0)
        y_predicted_threshold.append(row_output)
    
    return y_predicted_threshold
