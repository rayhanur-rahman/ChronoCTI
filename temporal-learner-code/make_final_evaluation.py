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
# print(xxx)


selectedTechniques = Utils.get_selected_techniques()
dataset: pd.DataFrame = Utils.get_dataset_dataframe()

FEATURE_TYPES = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
X_train, X_test, y_train, y_test, selected_features, labels, class_weights, reports, ttp_pairs = Utils.get_train_test_split(dataset, selectedTechniques, methodology = "heldout", ohe=True) # type: ignore

print(X_train.shape)


# Utils.perform_cross_validation()
# Utils.hyperParamOptimization()
# Utils.hyperParamOptimization()
# Utils.class_imbalance_handling(X_train, y_train, X_test, y_test)
# Utils.hyperParamOptimizationGenetic()
# Utils.FeatureSelectionGenetic()

clf = MultiOutputClassifier(xgb.XGBClassifier())
# clf = xgb.XGBClassifier()
# clf = xgb.XGBClassifier(colsample_bytree=1, learning_rate=0.1, max_depth=11, min_child_weight=0.5, n_estimators=400, subsample=1)
# {'max_depth': 5, 'learning_rate': 0.4, 'subsample': 0.956267615088915, 'n_estimators': 400, 'colsample_bytree': 0.6968173551467949, 'min_child_weight': 2.2811515976036127, 'max_delta_step': 1}
# clf = xgb.XGBClassifier(objective='multi:softprob', num_class=4)
clf = clf.fit(X_train, y_train)

# with open('saved_xgb_model.pkl','wb') as f:
#     pickle.dump(clf,f)

y_predicted = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)
y_prob = Utils.transpose_multiTaskOutput_to_predict_prob(clf.predict_proba(X_test))

print(classification_report(y_test, y_predicted, zero_division=0, target_names=labels))

print("CONCURRENT | Prec@K=50: ", Utils.compute_prec_k(y_test, y_prob, POS = 0, K = 50))
print("NEXT | Prec@K=50: ", Utils.compute_prec_k(y_test, y_prob, POS = 1, K = 50))
print("NULL | Prec@K=50: ", Utils.compute_prec_k(y_test, y_prob, POS = 2, K = 50))
print("OVERLAP | Prec@K=50: ", Utils.compute_prec_k(y_test, y_prob, POS = 3, K = 50))

print("CONCURRENT | Rec@K=50: ", Utils.compute_rec_k(y_test, y_prob, POS = 0, K = 50))
print("NEXT | Rec@K=50: ", Utils.compute_rec_k(y_test, y_prob, POS = 1, K = 50))
print("NULL | Prec@K=50: ", Utils.compute_prec_k(y_test, y_prob, POS = 2, K = 50))
print("OVERLAP | Rec@K=50: ", Utils.compute_rec_k(y_test, y_prob, POS = 3, K = 50))

print("CONCURRENT | Prec@K=100: ", Utils.compute_prec_k(y_test, y_prob, POS = 0))
print("NEXT | Prec@K=100: ", Utils.compute_prec_k(y_test, y_prob, POS = 1))
print("NULL | Prec@K=100: ", Utils.compute_prec_k(y_test, y_prob, POS = 2))
print("OVERLAP | Prec@K=100: ", Utils.compute_prec_k(y_test, y_prob, POS = 3))

print("CONCURRENT | Rec@K=100: ", Utils.compute_rec_k(y_test, y_prob, POS = 0))
print("NEXT | Rec@K=100: ", Utils.compute_rec_k(y_test, y_prob, POS = 1))
print("NULL | Prec@K=100: ", Utils.compute_prec_k(y_test, y_prob, POS = 2))
print("OVERLAP | Rec@K=100: ", Utils.compute_rec_k(y_test, y_prob, POS = 3))

print("Coverage error: ", coverage_error(y_test, y_prob))
print("label ranking average precision score: ", label_ranking_average_precision_score(y_test, y_predicted))
print("label ranking loss: ", label_ranking_loss(y_test, y_predicted))

print("Discounted Cumulative Gain: ", dcg_score(y_test, y_predicted, k = 100))
print("Normalized Discounted Cumulative Gain: ", ndcg_score(y_test, y_predicted, k = 100))

# print(dfg['CONCURRENT'].quantile(0.95))
# print(dfg['NEXT'].quantile(0.95))
# print(dfg['NULL'].quantile(0.95))
# print(dfg['OVERLAP'].quantile(0.95))

# print(tabulate.tabulate(df.sort_values(by=['CONCURRENT'], ascending=False).head(10), headers='keys', tablefmt='psql'))
# print(tabulate.tabulate(df.sort_values(by=['NEXT'], ascending=False).head(10), headers='keys', tablefmt='psql'))
# print(tabulate.tabulate(df.sort_values(by=['OVERLAP'], ascending=False).head(10), headers='keys', tablefmt='psql'))





# print("F0.5: ", fbeta_score(y_test, y_predicted, average='macro', beta=0.5))
# print("F2: ", fbeta_score(y_test, y_predicted, average='macro', beta=2))
# print("Accuracy: ", accuracy_score(y_test, y_predicted))
# print("Avg precision: ", average_precision_score(y_test, y_prob))
# print("Hamming loss: ", hamming_loss(y_test, y_predicted))
# print("Log loss: ", log_loss(y_test, y_predicted))
# print("Jaccard score: ", jaccard_score(y_test, y_predicted, average='macro'))
# print("ROC AUC: ", roc_auc_score(y_test, y_prob, average='macro'))

# print("TNR@CONCURRENT ", Utils.get_true_negative_rate(y_test, y_predicted, 0))
# print("TNR@NEXT ", Utils.get_true_negative_rate(y_test, y_predicted, 1))
# print("TNR@NULL ", Utils.get_true_negative_rate(y_test, y_predicted, 2))
# print("TNR@OVERLAP ", Utils.get_true_negative_rate(y_test, y_predicted, 3))

# print("FNR@CONCURRENT ", Utils.get_false_negative_rate(y_test, y_predicted, 0))
# print("FNR@NEXT ", Utils.get_false_negative_rate(y_test, y_predicted, 1))
# print("FNR@NULL ", Utils.get_false_negative_rate(y_test, y_predicted, 2))
# print("FNR@OVERLAP ", Utils.get_false_negative_rate(y_test, y_predicted, 3))

# print("NPV@CONCURRENT ", Utils.get_negative_predictive_value(y_test, y_predicted, 0))
# print("NPV@NEXT ", Utils.get_negative_predictive_value(y_test, y_predicted, 1))
# print("NPV@NULL ", Utils.get_negative_predictive_value(y_test, y_predicted, 2))
# print("NPV@OVERLAP ", Utils.get_negative_predictive_value(y_test, y_predicted, 3))

# print("FPR@CONCURRENT ", Utils.get_false_positive_rate(y_test, y_predicted, 0))
# print("FPR@NEXT ", Utils.get_false_positive_rate(y_test, y_predicted, 1))
# print("FPR@NULL ", Utils.get_false_positive_rate(y_test, y_predicted, 2))
# print("FPR@OVERLAP ", Utils.get_false_positive_rate(y_test, y_predicted, 3))

# print("FDR@CONCURRENT ", Utils.get_false_discovery_rate(y_test, y_predicted, 0))
# print("FDR@NEXT ", Utils.get_false_discovery_rate(y_test, y_predicted, 1))
# print("FDR@NULL ", Utils.get_false_discovery_rate(y_test, y_predicted, 2))
# print("FDR@OVERLAP ", Utils.get_false_discovery_rate(y_test, y_predicted, 3))

# print("FOR@CONCURRENT ", Utils.get_false_omission_rate(y_test, y_predicted, 0))
# print("FOR@NEXT ", Utils.get_false_omission_rate(y_test, y_predicted, 1))
# print("FOR@NULL ", Utils.get_false_omission_rate(y_test, y_predicted, 2))
# print("FOR@OVERLAP ", Utils.get_false_omission_rate(y_test, y_predicted, 3))

# print("PLR@CONCURRENT ", Utils.get_positive_likelihood_ratio(y_test, y_predicted, 0))
# print("PLR@NEXT ", Utils.get_positive_likelihood_ratio(y_test, y_predicted, 1))
# print("PLR@NULL ", Utils.get_positive_likelihood_ratio(y_test, y_predicted, 2))
# print("PLR@OVERLAP ", Utils.get_positive_likelihood_ratio(y_test, y_predicted, 3))

# print("NLR@CONCURRENT ", Utils.get_negative_likelihood_ratio(y_test, y_predicted, 0))
# print("NLR@NEXT ", Utils.get_negative_likelihood_ratio(y_test, y_predicted, 1))
# print("NLR@NULL ", Utils.get_negative_likelihood_ratio(y_test, y_predicted, 2))
# print("NLR@OVERLAP ", Utils.get_negative_likelihood_ratio(y_test, y_predicted, 3))

# print("prev-threshold@CONCURRENT ", Utils.get_prevalence_threshold(y_test, y_predicted, 0))
# print("prev-threshold@NEXT ", Utils.get_prevalence_threshold(y_test, y_predicted, 1))
# print("prev-threshold@NULL ", Utils.get_prevalence_threshold(y_test, y_predicted, 2))
# print("prev-threshold@OVERLAP ", Utils.get_prevalence_threshold(y_test, y_predicted, 3))

# print("TS@CONCURRENT ", Utils.get_threat_score(y_test, y_predicted, 0))
# print("TS@NEXT ", Utils.get_threat_score(y_test, y_predicted, 1))
# print("TS@NULL ", Utils.get_threat_score(y_test, y_predicted, 2))
# print("TS@OVERLAP ", Utils.get_threat_score(y_test, y_predicted, 3))

# print("BA@CONCURRENT ", Utils.get_balanced_accuracy(y_test, y_predicted, 0))
# print("BA@NEXT ", Utils.get_balanced_accuracy(y_test, y_predicted, 1))
# print("BA@NULL ", Utils.get_balanced_accuracy(y_test, y_predicted, 2))
# print("BA@OVERLAP ", Utils.get_balanced_accuracy(y_test, y_predicted, 3))

# Utils.compute_MUC(dataset, selectedTechniques, clf, FEATURE_TYPES=FEATURE_TYPES)


explainer = shap.Explainer(clf)
shap_values = explainer.shap_values(X_test)

feature_importances = []

feature_importances_data = []

for idx in range(len(shap_values)):
    value = shap_values[idx]
    value_transposed = np.transpose(value)
    
    importance = []
    
    for idx2 in range(len(value_transposed)):
        feature_vals = value_transposed[idx2]
        mean_val = statistics.quantiles(feature_vals, n=20)[-1]
        mean_val = statistics.mean(feature_vals)
        importance.append(mean_val)
    
    feature_importances_data.append(importance)


# effects of shap on imbalanced dataset: https://www.eftconference.business-school.ed.ac.uk/sites/eft_conference/files/2022-06/Chen-slides.pdf

features_df = pd.read_excel('Features.xlsx', sheet_name='features')

feature_types = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
feature_dict = {}
for item in feature_types:
    feature_dict[f'{item}'] = []

for idx, row in features_df.iterrows():
    for item in feature_types:
        if row['Type'] == item:
            feature_dict[f'{item}'].append(row['Feature'])


feature_importances_data = np.transpose(feature_importances_data)

for idx in range(len(feature_importances_data)):
    feature_importances.append({
        'Feature': selected_features[idx], 
        'Type': next((key for key in feature_dict.keys() if selected_features[idx] in feature_dict[key]), 'Categorical Embedding'),
        'CONCURRENT': feature_importances_data[idx][0],
        'NEXT': feature_importances_data[idx][1],
        'NULL': feature_importances_data[idx][2],
        'OVERLAP': feature_importances_data[idx][3]
    })


df = pd.DataFrame.from_dict(feature_importances)
dfg = df.groupby('Type')

for name, group in dfg:
    group_next = []
    group_concurrent = []
    group_null = []
    group_overlap = []
    
    for idx, row in group.iterrows():
        group_next.append(row['NEXT'])
        group_concurrent.append(row['CONCURRENT'])
        group_overlap.append(row['OVERLAP'])
        group_null.append(row['NULL'])
    
    print(name)
    print(statistics.quantiles(group_concurrent, n = 4))
    print(statistics.quantiles(group_next, n = 4))
    print(statistics.quantiles(group_null, n = 4))
    print(statistics.quantiles(group_overlap, n = 4))
    print('')