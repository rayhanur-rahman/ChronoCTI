import dgl.nn
import dgl.data
import dgl
import networkx as nx
import os
from torch.autograd import Variable
from more_itertools import powerset

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
from sklearn.metrics import *
import torch
import dgl.function as fn
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

os.environ["DGLBACKEND"] = "pytorch"

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques = json.load(file)

techniqueDict = {}
for te in selectedTechniques:
    techniqueDict[f'{te["id"]}'] = te['name']

ttp_pairs = []

for idx1 in range(len(selectedTechniques)):
    for idx2 in range(0, len(selectedTechniques)):
        if idx1 != idx2:
            ttp_pairs.append(
                (selectedTechniques[idx1], selectedTechniques[idx2]))

random.seed(0)

df_temporal = pd.read_excel('temporal_relation_dataset.xlsx')

train_reports = list(set(df_temporal.query(' mask == "train" ')['report'].tolist()))
eval_reports = list(set(df_temporal.query(' mask == "eval" ')['report'].tolist()))


def get_nx_graph(report_set, threshold = 95, FEATURE_SELECTION=False, FEATURE_TYPES = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']):
    
    
    features_df = pd.read_excel('Features.xlsx', sheet_name='features')

    feature_types = ['BASIC', 'SENTENCE', 'DISCOURSE', 'AMR', 'TIMEML', 'TIME SIGNAL HEURISTIC']
    feature_dict = {}
    for item in feature_types:
        feature_dict[f'{item}'] = []

    for idx, row in features_df.iterrows():
        for item in feature_types:
            if row['Type'] == item:
                feature_dict[f'{item}'].append(row['Feature'])
    
    dataset: pd.DataFrame = pd.read_pickle(f'saved_features_dataframes/dataset_df_threshold_{threshold}_v3.pkl')
    dataset = dataset.query(f' report in {report_set} ')
    dataset['Te1'] = dataset['T1']
    dataset['Te2'] = dataset['T2']
    dataset = pd.get_dummies(dataset, columns=['T1', 'T2'])

    ohe_feature_names = []

    for te in selectedTechniques:
        dataset[f"T1_{te['id']}"] = dataset[f"T1_{te['id']}"].astype(int)
        dataset[f"T2_{te['id']}"] = dataset[f"T2_{te['id']}"].astype(int)
        ohe_feature_names.append(f"T1_{te['id']}")
        ohe_feature_names.append(f"T2_{te['id']}")

    identifiers = ['report', 'T1', 'T2', 'threshold', 'Te1', 'Te2']
    labels = ['CONCURRENT', 'NEXT', 'NULL', 'OVERLAP']
    feature_names = list(set(dataset.columns) - set(identifiers) - set(labels) - set(ohe_feature_names))

    dataset.replace([np.inf, -np.inf], 0, inplace=True)

    for item in feature_names:
        dataset[item] = MinMaxScaler().fit_transform(np.array(dataset[item]).reshape(-1, 1))

    class_weights = []

    for label in labels:
        dfq = dataset.query(f' {label} == 1 ')
        class_weights.append(len(dataset) / (len(labels) * len(dfq)))

    node_feature_names = ['T1_P0', 'T1_P1', 'T1_P2', 'T1_P3', 'T1_P4', 'T2_P0', 'T2_P1', 'T2_P2', 'T2_P3', 'T2_P4']
    node_features_ohe = []
    
    for te in selectedTechniques:
        continue
        node_features_ohe.append(f"T_{te['id']}")

    node_feature_names.extend(node_features_ohe)

    edge_feature_names = list(set(feature_names) - set(node_feature_names))

    # selected_features = ['ELABORATION_NEXT',
    #                      'same_sentence',
    #                      'AFTER_TIMEML',
    #                      'BEFORE_TIMEML',
    #                      'consecutive_sentence_n4',
    #                      'SIMULTANEOUS_TIMEML',
    #                      'phi_AMR',
    #                      'DURING_TIMEML',
    #                      'INCLUDES_TIMEML',
    #                      'consecutive_sentence_p3',
    #                      'same_coreference_cluster',
    #                      'consecutive_sentence_p5',
    #                      'similarity',
    #                      'pmi_AMR', 'xy_AMR', 'supportXY_AMR', 'MISC_NEXT', 'IDENTITY_TIMEML', 'jaccard_AMR', 'MISC_COREF', 'supportY_AMR', 'confidence_AMR', 'nxny_AMR',
    #                      'consecutive_sentence_n3',
    #                      'consecutive_sentence_p4',
    #                      'consecutive_sentence_p1',
    #                      'consecutive_sentence_n2',
    #                      'ELABORATION_COREF',
    #                      'consecutive_sentence_n5',
    #                      'NEXT_COREF',
    #                      'consecutive_sentence_p2',
    #                      'consecutive_sentence_n1',
    #                      'NEXT_NEXT']

    
    # if not FEATURE_SELECTION:
    #     selected_features = feature_names

    selected_features = []
    for item in FEATURE_TYPES:
        for key in feature_dict.keys():
            if key == item:
                selected_features.extend(feature_dict[key])
    
    th = threshold/100
    datasetq1 = dataset.query(f'T1_P0 >= {th} and T2_P0 >= {th}')
    datasetq2 = dataset.query(f'(T1_P0 < {th} and T2_P0 < {th}) and (NEXT == 1 or OVERLAP == 1 or CONCURRENT == 1)')
    dataset = pd.concat([datasetq1, datasetq2], ignore_index = True)

    graph = nx.DiGraph()

    for idx, row in tqdm.tqdm(dataset.iterrows(), total=dataset.shape[0]):

        src_node_name = f'{row["Te1"]}@{row["report"]}'
        dst_node_name = f'{row["Te2"]}@{row["report"]}'

        if not graph.has_node(src_node_name):
            graph.add_node(src_node_name)

        if not graph.has_node(dst_node_name):
            graph.add_node(dst_node_name)

        src_node = graph.nodes[src_node_name]
        dst_node = graph.nodes[dst_node_name]

        for i in range(5):
            src_node[f'T_P{i}'] = row[f'T1_P{i}']
            dst_node[f'T_P{i}'] = row[f'T2_P{i}']

        for item in node_features_ohe:
            src_node[f'{item}'] = row[f'T1_{item[-5:]}']
            dst_node[f'{item}'] = row[f'T2_{item[-5:]}']

        if not graph.has_edge(src_node_name, dst_node_name):
            graph.add_edge(src_node_name, dst_node_name,src=src_node_name, dst=src_node_name)

        edge = graph.edges[src_node_name, dst_node_name]

        for feature in edge_feature_names:
            if feature in selected_features: edge[f'{feature}'] = row[feature]
            # edge[f'{feature}'] = row[feature]

        for label in labels:
            edge[f'{label}'] = row[f'{label}']

    print("original", len(graph.nodes()), len(graph.edges()))

    node_attrs = list(graph.nodes[list(graph.nodes())[0]].keys())
    edge_attrs = []

    for e in graph.edges():
        edge = graph.edges[e[0], e[1]]
        edge['class'] = torch.tensor([edge[f'{x}'] for x in labels])

    for edge in graph.edges():
        edge_attrs = list(graph.edges[edge[0], edge[1]].keys())
        break

    edge_attrs.remove('src')
    edge_attrs.remove('dst')

    for label in labels:
        edge_attrs.remove(label)

    return graph, node_attrs, edge_attrs, class_weights, labels


def get_dgl_graph(nx_graph, node_attrs, edge_attrs, k):

    subgraph = None

    if k == 1:
        subgraph = nx_graph
    else:
        query = []
        edges = list(nx_graph.edges())
        query = random.sample(edges, math.floor(k * len(nx_graph.edges())))
        subgraph = nx_graph.edge_subgraph(query).copy()

    graph = dgl.from_networkx(
        subgraph, node_attrs=node_attrs, edge_attrs=edge_attrs)

    feature_tensor = graph.ndata[node_attrs[0]]
    feature_tensor = torch.reshape(feature_tensor, (1, -1))
    for attr in node_attrs[1:]:
        feature_tensor = torch.concat(
            (feature_tensor, graph.ndata[f'{attr}'].reshape(1, -1)), 0)
    graph.ndata['feat'] = torch.transpose(feature_tensor, 0, 1)

    feature_tensor = graph.edata[edge_attrs[0]]
    feature_tensor = torch.reshape(feature_tensor, (1, -1))
    for attr in edge_attrs[1:-1]:
        feature_tensor = torch.concat(
            (feature_tensor, graph.edata[f'{attr}'].reshape(1, -1)), 0)
    
    if len(edge_attrs[1:]) > 0:
        graph.edata['feat'] = torch.transpose(feature_tensor, 0, 1)
        print(graph.edata['feat'].shape)
    else:
        graph.edata['feat'] = torch.ones(len(nx_graph.edges()), 1)
        print(graph.edata['feat'].shape)

    # graph = dgl.add_self_loop(graph)
    
    return graph, graph.ndata['feat'], graph.edata['feat'], graph.edata[f'class']


def get_mask(nx_graph, seed):
    train_mask = []
    test_mask = []
    random.seed(5 * seed)
    for i in range(len(nx_graph.edges())):
        rn = random.randint(1, 100)
        if rn <= 80:
            train_mask.append(True)
            test_mask.append(False)
        else:
            train_mask.append(False)
            test_mask.append(True)
    return train_mask, test_mask

class FocalLoss(nn.Module):
    def __init__(self, alpha=None, gamma=2):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        loss = (self.alpha[targets] * (1 - pt) ** self.gamma * ce_loss).mean()
        return loss


class sigmoidF1(nn.Module):

    def __init__(self, S = -1, E = 0):
        super(sigmoidF1, self).__init__()
        self.S = S
        self.E = E

    @torch.cuda.amp.autocast()
    def forward(self, y_hat, y):
        
        y_hat = torch.sigmoid(y_hat)

        b = torch.tensor(self.S)
        c = torch.tensor(self.E)

        sig = 1 / (1 + torch.exp(b * (y_hat + c)))

        tp = torch.sum(sig * y, dim=0)
        fp = torch.sum(sig * (1 - y), dim=0)
        fn = torch.sum((1 - sig) * y, dim=0)

        beta = 0
        
        sigmoid_f1 = 2*tp / (2*tp + fn + fp + 1e-16)
        cost = 1 - sigmoid_f1
        macroCost = torch.mean(cost)

        return macroCost

class SAGE(nn.Module):
    def __init__(self, in_feats, hid_feats, out_feats):
        super().__init__()
        self.conv1 = dglnn.SAGEConv(
            in_feats=in_feats, out_feats=hid_feats, aggregator_type='mean')
        self.conv2 = dglnn.SAGEConv(
            in_feats=hid_feats, out_feats=out_feats, aggregator_type='mean')
    def forward(self, graph, inputs):
        # inputs are features of nodes
        h = self.conv1(graph, inputs)
        h = F.relu(h)
        h = self.conv2(graph, h)
        return h

class GCONV(nn.Module):
    def __init__(self, in_feats, hid_feats1, hid_feats2, edge_feats):
        super().__init__()
        self.conv1 = dglnn.GraphConv(
            in_feats=in_feats, out_feats=hid_feats1, norm='both', allow_zero_in_degree=True)
        self.conv2 = dglnn.GraphConv(
            in_feats=hid_feats1, out_feats=hid_feats2, norm='both', allow_zero_in_degree=True)
        self.dropout = nn.Dropout(0.2)
        self.lin1 = nn.Linear(edge_feats, 8)
        self.lin2 = nn.Linear(8, 1)
    def forward(self, graph, inputs, edges):
        
        edges = self.lin1(edges)
        edges = self.lin2(edges)
        
        # inputs are features of nodes
        h = self.dropout(self.conv1(graph, feat = inputs, edge_weight=edges))
        h = F.relu(h)
        h = self.dropout(self.conv2(graph, feat = h, edge_weight=edges))
        h = F.relu(h)
        return h

class MLPPredictor(nn.Module):
    def __init__(self, in_features, out_classes):
        super().__init__()
        self.W = nn.Linear(in_features * 2, out_classes)
        self.dropout = nn.Dropout(0.2)
    def apply_edges(self, edges):
        h_u = edges.src['h']
        h_v = edges.dst['h']
        cat_out = torch.cat([h_u, h_v], dim = 1)
        cat_out = self.dropout(cat_out)
        score = self.W(cat_out)
        # score = F.relu(score)
        return {'score': score}

    def forward(self, graph, h):
        # h contains the node representations computed from the GNN defined
        # in the node classification section (Section 5.1).
        with graph.local_scope():
            graph.ndata['h'] = h
            graph.apply_edges(self.apply_edges)
            return graph.edata['score']

class DotProductPredictor(nn.Module):
    def forward(self, graph, h):
        # h contains the node representations computed from the GNN defined
        # in the node classification section (Section 5.1).
        with graph.local_scope():
            graph.ndata['h'] = h
            graph.apply_edges(fn.u_dot_v('h', 'h', 'score'))
            return graph.edata['score']

class Model(nn.Module):
    def __init__(self, in_features, hidden_features_1, hidden_features_2, edge_features, out_features):
        super().__init__()
        # self.linear = nn.Linear(in_features, hidden_features1)
        # self.sage = SAGE(in_features, hidden_features, out_features)
        self.sage = GCONV(in_features, hidden_features_1, hidden_features_2, edge_features)
        # self.pred = DotProductPredictor()
        # self.pred = MLPPredictor(nodefeatures.shape[1], edgeFeatures.shape[1])
        self.pred = MLPPredictor( hidden_features_2, out_features )
    def forward(self, g, x, e):
        # h = F.leaky_relu(self.dropout(self.linear(x)))
        h = self.sage(g, x, e)
        # h = self.sage(g, h, e)
        # print('***', h.shape)
        return self.pred(g, h)

def train(model, graph, node_features, edge_features, edge_labels, train_mask, test_mask, model_id):

    patience = 100
    best_score = 100
    last_scores = []
    precision_f1, recall_f1, macro_f1 = -1, -1, -1
    
    for epoch in range(1000000):
        pred = model(graph, node_features, edge_features)  # (36074, 1)
        pred_sigmoid = torch.sigmoid(pred)
        pred_sigmoid = (pred_sigmoid > 0.5).float()

        loss = nn.BCEWithLogitsLoss()
        loss = loss(pred[train_mask], edge_labels[train_mask].to(torch.float))
        opt.zero_grad()
        loss.backward()
        opt.step()
        train_loss = loss.item()

        if epoch % 1 == 0:
            # pred = model(graph, node_features, edge_features)  # (36074, 1)
            # pred_sigmoid = torch.sigmoid(pred)
            # pred_sigmoid = (pred_sigmoid > 0.5).float()
            
            loss = nn.BCEWithLogitsLoss()
            loss = loss(pred[test_mask],edge_labels[test_mask].to(torch.float))
            validation_loss = loss.item()
            precision_f1 = precision_score(edge_labels[test_mask].detach().numpy(), pred_sigmoid[test_mask].detach().numpy(), average='macro', zero_division=0)
            recall_f1 = recall_score(edge_labels[test_mask].detach().numpy(), pred_sigmoid[test_mask].detach().numpy(), average='macro', zero_division=0)
            macro_f1 = f1_score(edge_labels[test_mask].detach().numpy(), pred_sigmoid[test_mask].detach().numpy(), average='macro', zero_division=0)
            
            last_scores.append(validation_loss)
            
            if validation_loss < best_score:
                best_score = validation_loss
                torch.save(model, f'gnn_model_{model_id}.pt')
                # print(f'# {epoch} training: {round(train_loss, 3)} | validation: {round(validation_loss, 3)} | macro_f1: {round(macro_f1, 3)} | best score: {round(best_score, 3)}')
            
            if best_score < min(last_scores[ -1 * patience: ]) and len(last_scores) > patience:
                break
    
    return precision_f1, recall_f1, macro_f1
                        


dumps = []

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

for ft in feature_types_powerset:
    dump = {}
    dump['estimator'] = str('RGCN')
    dump['threshold'] = int(95)
    dump['feature_set'] = list(ft)
    dump['precision_macro'] = []
    dump['recall_macro'] = []
    dump['f1_macro'] = []
        
    for i in range(5):
        print(f'Fold: {i} | Features: {ft}')
        nx_graph, node_attrs, edge_attrs, class_weights, labels = get_nx_graph(train_reports, FEATURE_TYPES=ft)
        graph, node_features, edge_features, edge_labels = get_dgl_graph(nx_graph, node_attrs, edge_attrs, k=1)
        node_features = graph.ndata['feat']
        model = Model(node_features.shape[1], 256, 512, edge_features.shape[1], edge_labels.shape[1])
        opt = torch.optim.Adam(model.parameters())
        train_mask, test_mask = get_mask(nx_graph, i)
        # model = torch.load('gnn_model.pt')
        precision_f1, recall_f1, macro_f1 = train(model, graph, node_features, edge_features, edge_labels, train_mask, test_mask, i)
        print(precision_f1, recall_f1, macro_f1)
        
        dump['precision_macro'].append(precision_f1)
        dump['recall_macro'].append(recall_f1)
        dump['f1_macro'].append(macro_f1)
        
        dumps.append(dump)
    
json.dump(dumps, open(f'cross_validation/cross_validation_{95}_RGCN_without_ohe.json', 'w'))
        
    

