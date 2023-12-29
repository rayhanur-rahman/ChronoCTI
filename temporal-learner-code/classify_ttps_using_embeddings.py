from typing import List
import jsonlines
import json
import pandas as pd
from sentence_transformers import SentenceTransformer
from collections import OrderedDict
import tqdm
import torch
from torch import nn
import torch.nn.functional as F
from skorch import NeuralNetClassifier
from sklearn.metrics import classification_report
from skmultilearn.problem_transform import BinaryRelevance
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from skllm.config import SKLLMConfig
from skllm.preprocessing import GPTVectorizer
from sklearn.model_selection import *
from sklearn.multioutput import *

SKLLMConfig.set_openai_key("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")
SKLLMConfig.set_openai_org("org-c5HbhWhpWh6wlslt4heHhJB3")

sentence_transformer_model = SentenceTransformer('all-mpnet-base-v2')
openai_ada_model = GPTVectorizer()

selectedTechniques = []
file = open('selected_techniquesWName.json', 'r')
selectedTechniques: List = json.load(file)
selectedTechniques.sort(key=lambda v: v['id'])


SENTENCE_BERT_LENGTH = 768
OPENAI_ADA_LENGTH = 1536

labels_of_selected_techniques = [x['id'] for x in selectedTechniques]
openai_ada_embedding_features = [f'v_{x}' for x in range(OPENAI_ADA_LENGTH)]
sbert_embedding_features = [f'v_{x}' for x in range(SENTENCE_BERT_LENGTH)]

def load_openai_ada_embeddings(openai_ada_model, path_to_jsonl, path_to_pickle):
    dataframe_columns = []
    dataframe_columns.append('text')
    openai_ada_embedding_features = [f'v_{x}' for x in range(OPENAI_ADA_LENGTH)]
    dataframe_columns.extend(openai_ada_embedding_features)
    labels_of_selected_techniques = [x['id'] for x in selectedTechniques]
    dataframe_columns.extend(labels_of_selected_techniques)
    
    with jsonlines.open(f'{path_to_jsonl}') as reader:
        
        texts = []
        labels_list = []

        for data in tqdm.tqdm(reader):
            text = data['text']
            texts.append(text)
            
            if len(text) == 0:
                pass
            
            labels = OrderedDict(sorted(data['cats'].items()))
            labels = [labels[k] for k in labels.keys()]

            labels_list.append(labels)
    

        embeddings = list(openai_ada_model.fit_transform(texts))
        
        examples = []
        for text, embedding, labels in zip(texts, embeddings, labels_list):
        
            example = []
            example.append(text)
            example.extend(embedding)
            example.extend(labels)

            examples.append(example)

        df = pd.DataFrame(examples, columns=dataframe_columns)
        df.to_pickle(f'{path_to_pickle}')

def load_sentence_transformers_embeddings(sentence_transformer_model, path_to_jsonl, path_to_pickle):
    dataframe_columns = []
    dataframe_columns.append('text')
    embedding_features = [f'v_{x}' for x in range(SENTENCE_BERT_LENGTH)]
    dataframe_columns.extend(embedding_features)
    labels_of_selected_techniques = [x['id'] for x in selectedTechniques]
    dataframe_columns.extend(labels_of_selected_techniques)
    
    with jsonlines.open(f'{path_to_jsonl}') as reader:
        examples = []

        for data in tqdm.tqdm(reader):
            text = data['text']
            embedding = list(sentence_transformer_model.encode(text))
            labels = OrderedDict(sorted(data['cats'].items()))
            labels = [labels[k] for k in labels.keys()]

            example = []
            example.append(text)
            example.extend(embedding)
            example.extend(labels)

            examples.append(example)

        df = pd.DataFrame(examples, columns=dataframe_columns)
        df.to_pickle(f'{path_to_pickle}')


# load_sentence_transformers_embeddings(sentence_transformer_model, 'train_selected120.jsonl', 'train_selected120.pkl')
# load_sentence_transformers_embeddings(sentence_transformer_model, 'test_selected120.jsonl', 'test_selected120.pkl')

# load_openai_ada_embeddings(openai_ada_model, 'test_selected120.jsonl', 'test_selected120_ada.pkl')
# load_openai_ada_embeddings(openai_ada_model, 'train_selected120.jsonl', 'train_selected120_ada.pkl')

### cross validation
df_train: pd.DataFrame = pd.read_pickle('train_selected120_ada.pkl')
df_test: pd.DataFrame = pd.read_pickle('test_selected120_ada.pkl')
cdf = pd.concat([df_train, df_test], axis = 0, ignore_index=True)
X, y = cdf[openai_ada_embedding_features].values, cdf[labels_of_selected_techniques].values
n_splits = 10
kf = KFold(n_splits=n_splits, shuffle=True)
clf = MultiOutputClassifier(RandomForestClassifier())
scores = cross_val_score(clf, X, y, cv=kf, scoring='f1_macro')
print("cv scores of ada + random forest", scores)


df_train: pd.DataFrame = pd.read_pickle('train_selected120_sbert.pkl')
df_test: pd.DataFrame = pd.read_pickle('test_selected120_sbert.pkl')
cdf = pd.concat([df_train, df_test], axis = 0, ignore_index=True)
X, y = cdf[sbert_embedding_features].values, cdf[labels_of_selected_techniques].values
n_splits = 10
kf = KFold(n_splits=n_splits, shuffle=True)
clf = MultiOutputClassifier(RandomForestClassifier())
scores = cross_val_score(clf, X, y, cv=kf, scoring='f1_macro')
print("cv scores of sbert + random forest", scores)

### cross validation

print(xxx)


# df_train: pd.DataFrame = pd.read_pickle('train_selected120_sbert.pkl')
# df_test: pd.DataFrame = pd.read_pickle('test_selected120_sbert.pkl')

# X_train = df_train[openai_ada_embedding_features].values
X_train = df_train[sbert_embedding_features].values
y_train = df_train[labels_of_selected_techniques].values

print(X_train.shape)
print(y_train.shape)

class_weights = []

for label in labels_of_selected_techniques:
    dfq = df_train.query(f' {label} == 1 ')
    class_weights.append(
        len(df_train) / (len(labels_of_selected_techniques) * len(dfq)))

# X_test = df_test[openai_ada_embedding_features].values
X_test = df_test[sbert_embedding_features].values
y_test = df_test[labels_of_selected_techniques].values

print(X_test.shape)
print(y_test.shape)

clf = BinaryRelevance(classifier=RandomForestClassifier())
clf = clf.fit(X_train, y_train)
y_predicted = clf.predict(X_test)
print(classification_report(y_test, y_predicted, target_names=labels_of_selected_techniques))

class MultiClassClassifierModule(nn.Module):
    def __init__(
            self,
            input_dim=X_train.shape[1],
            hidden_dim1=512,
            hidden_dim2=256,
            output_dim=y_train.shape[1],
            dropout=0.2,
    ):
        super(MultiClassClassifierModule, self).__init__()
        self.dropout = nn.Dropout(dropout)

        self.hidden1 = nn.Linear(input_dim, hidden_dim1, dtype=torch.float64)
        self.hidden2 = nn.Linear(hidden_dim1, hidden_dim2, dtype=torch.float64)
        self.output = nn.Linear(hidden_dim2, output_dim, dtype=torch.float64)

    def forward(self, X, **kwargs):
        X = F.relu(self.hidden1(X))
        X = self.dropout(X)
        X = F.relu(self.hidden2(X))
        X = self.dropout(X)
        X = self.output(X)
        return X

clf = NeuralNetClassifier(MultiClassClassifierModule, train_split=None, max_epochs=100,
                          verbose=2, criterion=nn.BCEWithLogitsLoss(), iterator_train__shuffle=True)


# X_train = torch.tensor(X_train, dtype=torch.float64)
# y_train = torch.tensor(y_train, dtype=torch.float64)

# clf.fit(X_train, y_train)
# y_pred = clf.predict(X_test)

# print(classification_report(y_test, y_pred,
#       target_names=labels_of_selected_techniques, zero_division=0))
