import json, statistics

file = open('selected_techniquesWName.json', 'r')
# json.dump(selectedTechniques, file)
selectedTechniquesData = json.load(file)
file.close()


selectedTechniques = [te['id'] for te in selectedTechniquesData]
selectedTechniquesCount = [te['count'] for te in selectedTechniquesData]

dataframedict = {
    'technique': selectedTechniques, 
    'Count': selectedTechniquesCount
}

micro_f_trf = []
macro_f_trf = []

ttps_f = {}
for key in selectedTechniques: ttps_f[key] = []

for idx in range(0, 1):
    file = open(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/trfAll/metrics.json')
    data = json.load(file)
    
    micro_f_trf.append(data['cats_micro_f'])
    macro_f_trf.append(data['cats_macro_f'])
    
    
    f_list = data['cats_f_per_type']
    for key in selectedTechniques:
        f = f_list[key]['f']
        ttps_f[key].append(f)
        
    
    
    file.close()

dataframedict['trf'] = [statistics.median(ttps_f[x]) for x in ttps_f.keys()]

micro_f_lg = []
macro_f_lg = []

ttps_f = {}
for key in selectedTechniques: ttps_f[key] = []

for idx in range(0, 1):
    file = open(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/lgAll/metrics.json')
    data = json.load(file)
    
    micro_f_lg.append(data['cats_micro_f'])
    macro_f_lg.append(data['cats_macro_f'])
    
    f_list = data['cats_f_per_type']
    for key in selectedTechniques:
        f = f_list[key]['f']
        ttps_f[key].append(f)
    
    file.close()

dataframedict['lg'] = [statistics.median(ttps_f[x]) for x in ttps_f.keys()]

micro_f_w2v = []
macro_f_w2v = []

ttps_f = {}
for key in selectedTechniques: ttps_f[key] = []

for idx in range(0, 1):
    file = open(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/w2vAll/metrics.json')
    data = json.load(file)
    
    micro_f_w2v.append(data['cats_micro_f'])
    macro_f_w2v.append(data['cats_macro_f'])
    
    f_list = data['cats_f_per_type']
    for key in selectedTechniques:
        f = f_list[key]['f']
        ttps_f[key].append(f)
    
    file.close()

dataframedict['w2v'] = [statistics.median(ttps_f[x]) for x in ttps_f.keys()]

micro_f_rb = []
macro_f_rb = []

ttps_f = {}
for key in selectedTechniques: ttps_f[key] = []

for idx in range(0, 1):
    file = open(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaBaseAll/metrics.json')
    data = json.load(file)
    
    micro_f_rb.append(data['cats_micro_f'])
    macro_f_rb.append(data['cats_macro_f'])
    
    f_list = data['cats_f_per_type']
    for key in selectedTechniques:
        f = f_list[key]['f']
        ttps_f[key].append(f)
    
    file.close()

dataframedict['rb'] = [statistics.median(ttps_f[x]) for x in ttps_f.keys()]

micro_f_rc = []
macro_f_rc = []

ttps_f = {}
for key in selectedTechniques: ttps_f[key] = []

for idx in range(0, 1):
    file = open(f'/Users/rayhanurrahman/Workspace/ALL_TTPs_Classifiers/robertaCtiAll/metrics.json')
    data = json.load(file)
    
    micro_f_rc.append(data['cats_micro_f'])
    macro_f_rc.append(data['cats_macro_f'])
    
    f_list = data['cats_f_per_type']
    for key in selectedTechniques:
        f = f_list[key]['f']
        ttps_f[key].append(f)
    
    file.close()

dataframedict['rc'] = [statistics.median(ttps_f[x]) for x in ttps_f.keys()]

print(f'Spacy Trf | Micro | Mean: {statistics.mean(micro_f_trf)} | Median: {statistics.median(micro_f_trf)}')
print(f'Spacy Trf | Macro | Mean: {statistics.mean(macro_f_trf)} | Median: {statistics.median(macro_f_trf)}')

print(f'Spacy Lg | Micro | Mean: {statistics.mean(micro_f_lg)} | Median: {statistics.median(micro_f_lg)}')
print(f'Spacy Lg | Macro | Mean: {statistics.mean(macro_f_lg)} | Median: {statistics.median(macro_f_lg)}')

print(f'CTI w2v | Micro | Mean: {statistics.mean(micro_f_w2v)} | Median: {statistics.median(micro_f_w2v)}')
print(f'CTI w2v | Macro | Mean: {statistics.mean(macro_f_w2v)} | Median: {statistics.median(macro_f_w2v)}')

print(f'Roberta Base | Micro | Mean: {statistics.mean(micro_f_rb)} | Median: {statistics.median(micro_f_rb)}')
print(f'Roberta Base | Macro | Mean: {statistics.mean(macro_f_rb)} | Median: {statistics.median(macro_f_rb)}')

print(f'Roberta CTI| Micro | Mean: {statistics.mean(micro_f_rc)} | Median: {statistics.median(micro_f_rc)}')
print(f'Roberta CTI | Macro | Mean: {statistics.mean(macro_f_rc)} | Median: {statistics.median(macro_f_rc)}')

import pandas as pd

df = pd.DataFrame(dataframedict)
df.to_excel('comparisonv2.xlsx')

