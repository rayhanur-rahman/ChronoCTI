from ast import pattern
import math
import statistics
from unittest import result
import pandas as pd
import json
import re
from sklearn.metrics import auc
import evaluationMetrics
import tqdm
import seaborn as sns
import matplotlib.pyplot as plt
from tabulate import tabulate

selectedTechniquesData = json.load( open('selected_techniquesWName.json') )
exampleCount = sum([x['count'] for x in selectedTechniquesData])
randomClassifierProbability = sum([ math.pow(x['count']/exampleCount, 2) for x in selectedTechniquesData ])
PATH_TO_CTI_REPORTS_SENTENCES = 'unseen_report_sentence.json' # action_sentence.json
PATH_TO_CTI_REPORTS_SENTENCES_WITH_METADATA = 'unseen_report_sentence_with_metadata.json' # report_sentences.json
PATH_TO_TTPS_PREDICTION_OUTPUT_AS_DIRECTORY = 'unseen_reports_prediction' # results3/
PATH_TO_REPORT_SENTENCE_WITH_PREDICTION = 'unseen_report_sentences_with_prediction.json' # report_sentences_with_prediction_v2

def get_report_prediction():

    examples = json.load(open(f'{PATH_TO_CTI_REPORTS_SENTENCES}'))
    examplesOut = []

    p1 = r'[/]{0,1}r-dfir-[\d]+'
    p2 = r'[/]{0,1}r-[\d]+'
    p3 = r':::S[\d]+'

    idx = 0

    for idx in tqdm.tqdm(range(len(examples))):
        ex = examples[idx]
        id = ex['id']
        
        resultText = ''
        
        result = re.search(p1, id)
        if result:
            resultText = result.group(0)
        else:
            result = re.search(p2, id)
            if result: resultText = result.group(0)
        
        if resultText.startswith('/'):
            resultText = resultText[1:]
        
        ex['report'] = resultText
        
        result = re.search(p3, id)
        if result: resultText = result.group(0)
        
        ex['line'] = int(resultText[4:])
        
        ex['index'] = idx
        examplesOut.append(ex)
        idx += 1

    json.dump(examplesOut, open(f'{PATH_TO_CTI_REPORTS_SENTENCES_WITH_METADATA}', 'w'))


    examples = json.load(open(f'{PATH_TO_CTI_REPORTS_SENTENCES_WITH_METADATA}'))
    examplesOut = []

    for ex in tqdm.tqdm(examples, total=len(examples)):
        index = ex['index']
        prediction = json.load(open(f'{PATH_TO_TTPS_PREDICTION_OUTPUT_AS_DIRECTORY}/{index}.json'))
        ex['ttps'] = prediction['ttps']
        examplesOut.append(ex)


    json.dump(examplesOut, open(f'{PATH_TO_REPORT_SENTENCE_WITH_PREDICTION}', 'w'))

    input('end of program. press CTRL + C to stop...')

# get_report_prediction()

# df = pd.read_excel('temporal_relation_dataset.xlsx')

# examples = {}

# for row in df.itertuples():
#     if row.Report not in examples.keys():
#         examples[f'{row.Report}'] = []
    
#     if not str(row.T1).startswith('n'): 
#         if str(row.T1)[:5] not in examples[f'{row.Report}']: examples[f'{row.Report}'].append(str(row.T1)[:5])
    
#     if not str(row.T2).startswith('n'): 
#         if str(row.T2)[:5] not in examples[f'{row.Report}']: examples[f'{row.Report}'].append(str(row.T2)[:5]) 

#     x = 0

# json.dump(examples, open('report_containing_ttps.json', 'w'))


dataset_sentence_ttps_mapping = json.load(open("report_sentences_with_prediction_v2.json"))
dataset_ttps_reports_mapping = json.load(open("report_containing_ttps.json"))
selectecTechniques = json.load(open("selected_techniquesWName.json"))
labels = [x['id'] for x in selectecTechniques]

print(f'label cardinality: {evaluationMetrics.calculate_label_cardinality(dataset_ttps_reports_mapping)}')
print(f'label density: {evaluationMetrics.calculate_label_density(dataset_ttps_reports_mapping, selectecTechniques)}')

data = {
    'th': [], 
    'prec': [],
    'rec': [],
    'f1': []
}

for prediction_threshold in range(1, 100, 1):
    
    data['th'].append(prediction_threshold)
    
    precision_list = []
    recall_list = []
    f1_list = []
    f2_list = []
    f1_2_list = []
    hamming_loss_list = []
    jaccard_index_list = []
    exact_match_list = []

    prediction_ttps_reports_mapping = {}

    for item in dataset_sentence_ttps_mapping:
        
        if not item['report'] in prediction_ttps_reports_mapping.keys():
            prediction_ttps_reports_mapping[f'{item["report"]}'] = []
            for element in item['ttps']:
                if element['prob'] >= prediction_threshold:
                    prediction_ttps_reports_mapping[f'{item["report"]}'].append(element['id'])
        else:
            for element in item['ttps']:
                if element['prob'] >= prediction_threshold:
                    prediction_ttps_reports_mapping[f'{item["report"]}'].append(element['id'])
                    
    for key in prediction_ttps_reports_mapping.keys():
        prediction_ttps_reports_mapping[key] = list(set(prediction_ttps_reports_mapping[key]))


    for key in prediction_ttps_reports_mapping.keys():
        actual = dataset_ttps_reports_mapping[key]
        prediction = prediction_ttps_reports_mapping[key]      
        
        precision = evaluationMetrics.calculate_precision(prediction, actual)
        recall = evaluationMetrics.calculate_recall(prediction, actual)
        
        f1 = evaluationMetrics.calculate_f_score(precision, recall, 1)
        f2 = evaluationMetrics.calculate_f_score(precision, recall, 2)
        f1_2 = evaluationMetrics.calculate_f_score(precision, recall, 0.5)
        
        jaccard_index = evaluationMetrics.calculate_jaccard_index(prediction, actual)
        hamming_loss = evaluationMetrics.calculate_hamming_loss(prediction, actual, labels)
        exact_match = evaluationMetrics.calculate_exact_match(prediction, actual)
        
        precision_list.append(precision)
        recall_list.append(recall)
        f1_list.append(f1)
        f2_list.append(f2)
        f1_2_list.append(f1_2)
        hamming_loss_list.append(hamming_loss)
        jaccard_index_list.append(jaccard_index)
        exact_match_list.append(exact_match)

    # print(f"Precision@{prediction_threshold} =", prediction_threshold, statistics.mean(precision_list), statistics.quantiles(precision_list, n = 4))
    # print(f"Recall@{prediction_threshold} =", prediction_threshold, statistics.mean(recall_list), statistics.quantiles(recall_list, n = 4))
    # print(f"F1@{prediction_threshold} =", prediction_threshold, statistics.mean(f1_list), statistics.quantiles(f1_list, n = 4))
    # print(f"F2@{prediction_threshold} =", prediction_threshold, statistics.mean(f2_list), statistics.quantiles(f2_list, n = 4))
    # print(f"F0.5@{prediction_threshold} =", prediction_threshold, statistics.mean(f1_2_list), statistics.quantiles(f1_2_list, n = 4))
    
    # print(f"Hamming Loss@{prediction_threshold} =", prediction_threshold, statistics.mean(hamming_loss_list), statistics.quantiles(hamming_loss_list, n = 4))
    # print(f"Jaccard Index@{prediction_threshold} =", prediction_threshold, statistics.mean(jaccard_index_list), statistics.quantiles(jaccard_index_list, n = 4))
    # print(f"Exact Match@{prediction_threshold} =", prediction_threshold, statistics.mean(exact_match_list), statistics.quantiles(exact_match_list, n = 4))
    
    data['prec'].append(statistics.median(precision_list))
    data['rec'].append(statistics.median(recall_list))
    data['f1'].append(statistics.median(f1_list))
    
    # print('\n')






prediction_ttps_reports_mapping_with_ranking = {}

for item in dataset_sentence_ttps_mapping:
    
    if not item['report'] in prediction_ttps_reports_mapping_with_ranking.keys():
        prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}'] = {}
        prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'] = {}
        for element in item['ttps']:
            prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'][f'{element["id"]}'] = []
            prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'][f'{element["id"]}'].append(element['prob'])
    else:
        for element in item['ttps']:
            if not element['id'] in prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'].keys():
                prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'][f'{element["id"]}'] = []
                prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'][f'{element["id"]}'].append(element['prob'])
            else:
                prediction_ttps_reports_mapping_with_ranking[f'{item["report"]}']['ttps'][f'{element["id"]}'].append(element['prob'])

for report_key in prediction_ttps_reports_mapping_with_ranking.keys():
    prediction_ttps_reports_mapping_with_ranking[report_key]['rank'] = []
    for ttps_key in prediction_ttps_reports_mapping_with_ranking[report_key]['ttps'].keys():
        maximum = max(prediction_ttps_reports_mapping_with_ranking[report_key]['ttps'][ttps_key])
        prediction_ttps_reports_mapping_with_ranking[report_key]['rank'].append((ttps_key, maximum))

    prediction_ttps_reports_mapping_with_ranking[report_key]['rank'].sort(key = lambda v : v[1], reverse = True)
    

for rank_threshold in range(1, 30):
    precision_at_k_list = []
    recall_at_k_list = []
    f1_at_k_list = []
    
    
    for key in prediction_ttps_reports_mapping_with_ranking.keys():
        actual = dataset_ttps_reports_mapping[key]
        predicted = [x[0] for x in prediction_ttps_reports_mapping_with_ranking[key]['rank'][0:rank_threshold]]
        
        precision = evaluationMetrics.calculate_precision(predicted, actual)
        recall = evaluationMetrics.calculate_recall(predicted, actual)
        f1 = evaluationMetrics.calculate_f_score(precision, recall, 1)
        
        precision_at_k_list.append(precision)
        recall_at_k_list.append(recall)
        f1_at_k_list.append(f1)
    
    # print(f"Precision@{rank_threshold} =", rank_threshold, statistics.mean(precision_at_k_list), statistics.quantiles(precision_at_k_list, n = 4))
    # print(f"Recall@{rank_threshold} =", rank_threshold, statistics.mean(recall_at_k_list), statistics.quantiles(recall_at_k_list, n = 4))
    # print(f"F1@{rank_threshold} =", rank_threshold, statistics.mean(f1_at_k_list), statistics.quantiles(f1_at_k_list, n = 4))
    # print('')


precision_at_mak_list = []
recall_at_mak_list = []
f1_at_mak_list = []

for key in prediction_ttps_reports_mapping_with_ranking.keys():
    precision_at_ak_list = []
    recall_at_ak_list = []
    f1_at_ak_list = []
    
    for rank_threshold in range(1, 18):    
        actual = dataset_ttps_reports_mapping[key]
        predicted = [x[0] for x in prediction_ttps_reports_mapping_with_ranking[key]['rank'][0:rank_threshold]]
        
        precision = evaluationMetrics.calculate_precision(predicted, actual)
        recall = evaluationMetrics.calculate_recall(predicted, actual)
        f1 = evaluationMetrics.calculate_f_score(precision, recall, 1)
        
        precision_at_ak_list.append(precision)
        recall_at_ak_list.append(recall)
        f1_at_ak_list.append(f1)

    precision_at_mak_list.append(statistics.mean(precision_at_ak_list))
    recall_at_mak_list.append(statistics.mean(recall_at_ak_list))
    f1_at_mak_list.append(statistics.mean(f1_at_ak_list))

    
# print("MAP@K ", statistics.mean(precision_at_mak_list))
# print("MAR@K =", statistics.mean(recall_at_mak_list))
# print("MAF@K =", statistics.mean(f1_at_mak_list))
# print('')


df = pd.DataFrame(data)
df = pd.melt(df, id_vars=['th'], value_vars=['prec', 'rec', 'f1'], value_name='score', var_name='metric')
print(tabulate(df.head(300), tablefmt='psql'))

sns.lineplot(x='th', y='score', hue='metric', data=df, markers=['o', 'X', '*'], markerfacecolor='brown', markersize=10).set(title='', xlabel='Prediction Threshold', ylabel='Score')
plt.show()