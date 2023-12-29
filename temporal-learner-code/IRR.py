import json
import statistics
import pandas as pd
import tabulate

def calculate_IRR_TTPs_dataset():
    
    jsonFileIds = [500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500,
                6000, 6500, 7000, 7500, 8000, 8500, 9000, 9500, 10000, 10500, 11000, 11106]
    
    dataset = []
    for item in jsonFileIds:
        dataset += json.load(open(f'/Users/rayhanurrahman/PycharmProjects/TTPs2HGraph/data/prediction_dump_{item}.json'))
        
    selectedTechniques = []
    file = open('selected_techniquesWName.json', 'r')
    selectedTechniques = json.load(file)
    selectedTechniques = [x['id'] for x in selectedTechniques]
    
    bmData = json.load(open(f"IRR_data/ttpsDatasetBM.json"))
    bmData_pids = [x['pId'] for x in bmData]
    rrData = [x for x in dataset if x['pId'] in bmData_pids]
    
    scores = []
    
    for te in selectedTechniques:
        yes_rr = 0
        yes_bm = 0
        
        no_rr, no_bm = 0, 0
        
        both_yes = 0
        both_no = 0
        
        for idx in range(len(rrData)):
            rr = rrData[idx]
            bm = bmData[idx]
            if te in str(rr['default'])[0:5] and rr['defaultIsFound']['success'] == True:
                both_yes += 1
                yes_rr += 1
                yes_bm += 1
            else:
                rrLabels = [str(x['tId'])[:5] for x in rr['others'] if x['isPresent'] == True]
                bmLabels = [str(x['tId'])[:5] for x in bm['others'] if x['isPresent'] == True]
                
                if te in rrLabels and te in bmLabels: 
                    both_yes += 1
                if te not in rrLabels and te not in bmLabels: 
                    both_no += 1
                
                if te in rrLabels: 
                    yes_rr += 1
                
                if te in bmLabels: 
                    yes_bm += 1
                
                if te not in rrLabels: 
                    no_rr += 1
                
                if te not in bmLabels: 
                    no_bm += 1
                
        P_0 = (both_yes + both_no) / len(rrData)
        P_yes = (yes_rr/len(rrData)) * (yes_bm/len(rrData))
        P_no = (no_rr/len(rrData)) * (no_bm/len(rrData))
        P_e = P_yes + P_no
        
        try:
            score = (P_0 - P_e) / (1 - P_e)
        except:
            score = 0
        scores.append(score)
        

    print(statistics.mean(scores), statistics.median(scores), statistics.stdev(scores))
    

    
    pass

def calculate_IRR_discourse_dataset():
    
    rr_next = pd.read_excel('IRR_data/rr_next.xlsx')
    rr_coref = pd.read_excel('IRR_data/rr_coref.xlsx')
    
    qm_coref = pd.read_excel('IRR_data/bm_qm_all.xlsx', sheet_name='Sheet1')
    qm_next = pd.read_excel('IRR_data/bm_qm_all.xlsx', sheet_name='Sheet2')
    
    rr_dataset = []
    
    for idx, row in rr_next.iterrows():
        item = {}
        item['id'] = row['id']
        item['label'] = str(row['relation']).lower()
    
        rr_dataset.append(item)
    
    for idx, row in rr_coref.iterrows():
        item = {}
        item['id'] = row['id']
        item['label'] = str(row['relation']).lower()
    
        rr_dataset.append(item)
    
    qm_dataset = []
    
    for idx, row in qm_next.iterrows():
        item = {}
        item['id'] = row['id']
        if len(str(row['relation_QM'])) > 0:
            item['label'] = str(row['relation_QM']).lower()
        elif len(str(row['relation_BW'])) > 0:
            item['label'] = str(row['relation_BW']).lower()
    
        qm_dataset.append(item)
    
    for idx, row in qm_coref.iterrows():
        item = {}
        item['id'] = row['id']
        item['label'] = str(row['relation']).lower()
    
        qm_dataset.append(item)
    
    
    LABLELS = ['next', 'elaboration', 'misc', 'list', 'if_else']
    
    scores = []
    
    for label in LABLELS:
        yes_rr = 0
        yes_qm = 0
        
        no_rr, no_qm = 0, 0
        
        both_yes = 0
        both_no = 0
        
        for idx in range(len(rr_dataset)):
            data_rr = rr_dataset[idx]
            data_qm = qm_dataset[idx]
            
            if data_rr['id'] != data_qm['id']:
                continue
            
            if data_rr['label'] == label and data_qm['label'] == label:
                both_yes += 1
            
            if data_rr['label'] != label and data_qm['label'] != label:
                both_no += 1
            
            if data_rr['label'] == label:
                yes_rr += 1
            
            if data_qm['label'] == label:
                yes_qm += 1
            
            if data_rr['label'] != label:
                no_rr += 1
            
            if data_qm['label'] != label:
                no_qm += 1
            
        
        P_0 = (both_yes + both_no) / len(rr_dataset)
        P_yes = (yes_rr/len(rr_dataset)) * (yes_qm/len(rr_dataset))
        P_no = (no_rr/len(rr_dataset)) * (no_qm/len(rr_dataset))
        P_e = P_yes + P_no
        
        score = 0
        
        try:
            score = (P_0 - P_e) / (1 - P_e)
        except:
            score = 0
        
        scores.append(score)
        
            
    print(scores)
    print(statistics.mean(scores), statistics.median(scores), statistics.stdev(scores))
    
    pass


def calculate_IRR_temporal_dataset():
    
    rr_dataset = pd.read_excel('IRR_data/temporal_relation_dataset.xlsx')
    
    bw_dataset_p1 = pd.read_excel('IRR_data/technique_relation_dataset_BW.xlsx', sheet_name='sheet1')
    bw_dataset_p2 = pd.read_excel('IRR_data/technique_relation_dataset_BW.xlsx', sheet_name='sheet2')
    bw_dataset_p3 = pd.read_excel('IRR_data/technique_relation_dataset_QM.xlsx')
    bw_dataset = pd.concat([bw_dataset_p1, bw_dataset_p2, bw_dataset_p3])
    
    labels = ['NEXT', 'CONCURRENT', 'OVERLAP']
    

    scores = []
    
    reports = list(set(rr_dataset['Id'].tolist()))
    # reports = ['r-3']
    selectedTechniques = []
    file = open('selected_techniquesWName.json', 'r')
    selectedTechniques = json.load(file)
    selectedTechniques = [x['id'] for x in selectedTechniques]
    selectedTechniques.sort()
    
    for label in labels:
        
        if label == 'NEXT':            
            rr_dataset_next = []
            bw_dataset_next = []
            
            for idx, row in rr_dataset.iterrows():
                if row['relation'] == label:                    
                    t1, t2 = str(row['T1'])[:5], str(row['T2'])[:5]
                    rr_dataset_next.append({
                        'Id': row['Id'],
                        'T1': t1,
                        'T2': t2,
                        'relation': label
                    })
            
            for idx, row in bw_dataset.iterrows():
                if row['relation'] == label:                    
                    t1, t2 = str(row['T1'])[:5], str(row['T2'])[:5]
                    bw_dataset_next.append({
                        'Id': row['Id'],
                        'T1': t1,
                        'T2': t2,
                        'relation': label
                    })
            
            yes_rr = 0
            yes_bw = 0
            
            no_rr, no_bw = 0, 0
            
            both_yes = 0
            both_no = 0
            
            
            for report in reports:
                for te1 in selectedTechniques:
                    for te2 in selectedTechniques:
                        if te1 != te2:
                            
                            if te1 == 'T1566' and te2 == 'T1204':
                                pass
                            
                            if len([x for x in rr_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) > 0 and len([x for x in bw_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) > 0:
                                both_yes += 1
                                
                            if len([x for x in rr_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) == 0 and len([x for x in bw_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) == 0:
                                both_no += 1
                            
                            if len([x for x in rr_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) > 0:
                                yes_rr += 1
                            
                            if len([x for x in bw_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) > 0:
                                yes_bw += 1
                            
                            if len([x for x in rr_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) == 0:
                                no_rr += 1
                            
                            if len([x for x in bw_dataset_next if x['Id'] == report and x['T1'] == te1 and x['T2'] == te2 ]) == 0:
                                no_bw += 1
                            
                            pass
            score = 0
            dataset_size = len(reports) * len(selectedTechniques) * len(selectedTechniques) - len(selectedTechniques)
            P_0 = (both_yes + both_no) / dataset_size
            P_yes = (yes_rr/dataset_size) * (yes_bw/dataset_size)
            P_no = (no_rr/dataset_size) * (no_bw/dataset_size)
            P_e = P_yes + P_no
            
            score = 0
            
            try:
                score = (P_0 - P_e) / (1 - P_e)
            except:
                score = 0
            
            scores.append(score)      
            
        else:
            rr_dataset_other = []
            bw_dataset_other = []
            
            for idx, row in rr_dataset.iterrows():
                if row['relation'] == label:                    
                    t1, t2 = str(row['T1'])[:5], str(row['T2'])[:5]
                    rr_dataset_other.append({
                        'Id': row['Id'],
                        'T1': t1,
                        'T2': t2,
                        'relation': label
                    })
            
            for idx, row in bw_dataset.iterrows():
                if row['relation'] == label:                    
                    t1, t2 = str(row['T1'])[:5], str(row['T2'])[:5]
                    bw_dataset_other.append({
                        'Id': row['Id'],
                        'T1': t1,
                        'T2': t2,
                        'relation': label
                    })
            
            yes_rr = 0
            yes_bw = 0
            
            no_rr, no_bw = 0, 0
            
            both_yes = 0
            both_no = 0
            
            for report in reports:
                for idx1 in range(len(selectedTechniques)):
                    for idx2 in range(idx1+1, len(selectedTechniques)):
                        
                        te1 = selectedTechniques[idx1]
                        te2 = selectedTechniques[idx2]
                        
                        if len([x for x in rr_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) > 0 and len([x for x in bw_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) > 0:
                            both_yes += 1
                            
                        if len([x for x in rr_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) == 0 and len([x for x in bw_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) == 0:
                            both_no += 1
                        
                        if len([x for x in rr_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) > 0:
                            yes_rr += 1
                        
                        if len([x for x in bw_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) > 0:
                            yes_bw += 1
                        
                        if len([x for x in rr_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) == 0:
                            no_rr += 1
                        
                        if len([x for x in bw_dataset_other if x['Id'] == report and ((x['T1'] == te1 and x['T2'] == te2) or (x['T2'] == te1 and x['T1'] == te2)) ]) == 0:
                            no_bw += 1
                        
                        pass
            score = 0
            dataset_size = (len(reports) * len(selectedTechniques) * len(selectedTechniques) - len(selectedTechniques))/2
            P_0 = (both_yes + both_no) / dataset_size
            P_yes = (yes_rr/dataset_size) * (yes_bw/dataset_size)
            P_no = (no_rr/dataset_size) * (no_bw/dataset_size)
            P_e = P_yes + P_no
            
            score = 0
            
            try:
                score = (P_0 - P_e) / (1 - P_e)
            except:
                score = 0
            
            scores.append(score)      
        

        
        pass
    
    print(scores)
    print(statistics.mean(scores), statistics.median(scores), statistics.stdev(scores))
    pass


def calculate_IRR_pattern_group():
    df = pd.read_excel('IRR_data/patterns_v2.xlsx', sheet_name='combined')
    
    df_trimmed = df[['Pattern', 'Count', 'Type', 'Category']]
    
    dfg = df_trimmed.groupby(['Category'])['Count'].sum()
    print(dfg)
    
    pattern_data = {
        'name': [], 'pairs' : [], 'count': []
    }

    for name, group in dfg:        
        pattern_data['name'].append(name)
        patterns = []
        
        for idx, row in group.iterrows():
            patterns.append(row['Pattern'])
            
        print(tabulate.tabulate(group[['Pattern', 'Type', 'Count']], showindex=False, headers='keys', tablefmt='psql'))
        
        pass
        
        # pattern_data['pairs'].append(patterns)
        # pattern_data['count'].append(len(patterns))
    
    
    # df_pattern = pd.DataFrame.from_dict(pattern_data)
    # df_pattern.sort_values(by = 'count', ascending=False, inplace=True)
    
    # print(tabulate.tabulate(df_pattern, headers='keys', showindex=False, tablefmt='psql'))
    
    return
    
    LABELS = [x for x in list(set(df['RR-coded'].tolist())) if str(x) != 'nan']
    
    rr_dataset = []
    
    for idx, row in df.iterrows():
        item = {}
        item['id'] = row['Pattern']
        item['label'] = str(row['RR-coded']).lower()
    
        rr_dataset.append(item)
    
    
    bw_dataset = []
    
    for idx, row in df.iterrows():
        item = {}
        item['id'] = row['Pattern']
        item['label'] = str(row['BW-coded']).lower()
    
        bw_dataset.append(item)
    
    
    scores = []
    
    for label in LABELS:
        yes_rr = 0
        yes_bw = 0
        
        no_rr, no_bw = 0, 0
        
        both_yes = 0
        both_no = 0
        
        for idx in range(len(rr_dataset)):
            data_rr = rr_dataset[idx]
            data_bw = bw_dataset[idx]
            
            if data_rr['id'] != data_bw['id']:
                continue
            
            if data_rr['label'] == label and data_bw['label'] == label:
                both_yes += 1
            
            if data_rr['label'] != label and data_bw['label'] != label:
                both_no += 1
            
            if data_rr['label'] == label:
                yes_rr += 1
            
            if data_bw['label'] == label:
                yes_bw += 1
            
            if data_rr['label'] != label:
                no_rr += 1
            
            if data_bw['label'] != label:
                no_bw += 1
            
        
        P_0 = (both_yes + both_no) / len(rr_dataset)
        P_yes = (yes_rr/len(rr_dataset)) * (yes_bw/len(rr_dataset))
        P_no = (no_rr/len(rr_dataset)) * (no_bw/len(rr_dataset))
        P_e = P_yes + P_no
        
        score = 0
        
        try:
            score = (P_0 - P_e) / (1 - P_e)
        except:
            score = 0
        
        scores.append(score)
        
            
    print(scores)
    print(statistics.mean(scores), statistics.median(scores), statistics.stdev(scores))
    
    
    
    pass

calculate_IRR_pattern_group()

# calculate_IRR_temporal_dataset()
# [0.4683839055363173, 0.4938078936881585, 0.47433936174494873, 0.49793011350990546]
# 0.4836153186198325 0.4840736277165536 0.01445500212998601


# calculate_IRR_discourse_dataset()
# [0.3957764170696449, 0.49199051034077096, 0.4664678037802508, 0.5575711324861794, 0.6125679396664001]
# 0.5048747606686492 0.49199051034077096 0.08354381369281351

# calculate_IRR_TTPs_dataset()
# 0.7358516643771477 0.8315395848311 0.2460247553296824

def cross_validate_technique_classifiers():
    DIRECTORY = '/Users/rayhanurrahman/Downloads/cross_validation/'
    models = ['lgAll', 'trfAll', 'w2vAll', 'robertaBaseAll', 'robertaCtiAll']
    
    model_scores = {}
    
    for model in models:
        results = []
        for idx in range(5):
            data = json.load(open(f'{DIRECTORY}/metrics-{model}-{idx}.json'))
            loss = json.load(open(f'{DIRECTORY}/meta-{model}-{idx}.json'))['performance']['textcat_multilabel_loss']
            # results.append(data['cats_macro_f'])
            results.append(loss)
        
        model_scores[f'{model}'] = results
    
    
    for key in model_scores.keys():
        print(f'{key}: {statistics.mean( model_scores[key] )} | {statistics.median( model_scores[key] )} | {statistics.stdev( model_scores[key] )}')
    
    pass

# cross_validate_technique_classifiers()

def construct_evaluation_table_for_temporal_classifiers():
    learner_names = ['RGCN', 'TabNet', 'RandomForestClassifier', 'AdaBoostClassifier', 'ExtraTreesClassifier', 'HistGradientBoostingClassifier', 'MultinomialNB', 'BernoulliNB', 'GaussianNB', 'KNeighborsClassifier', 'DecisionTreeClassifier', 'ExtraTreeClassifier', 'XGBClassifier', 'MLPClassifier', 'PassiveAggressiveClassifier', 'RidgeClassifier', 'SGDClassifier', 'NearestCentroid']
    
    feature_sets = {
        'Time Signal': [
            "BASIC",
            "TIME SIGNAL HEURISTIC",
            "TIMEML"
        ],
        'Time Signal + Sentence': [
            "BASIC",
            "SENTENCE",
            "TIMEML",
            "TIME SIGNAL HEURISTIC"
        ],
        'Time Signal + Sentence + Discourse': [
            "BASIC",
            "SENTENCE",
            "DISCOURSE",
            "TIMEML",
            "TIME SIGNAL HEURISTIC"
        ],
        'Time Signal + Sentence + Discourse + Apriori': [
            "BASIC",
            "SENTENCE",
            "DISCOURSE",
            "TIMEML",
            "TIME SIGNAL HEURISTIC",
            "AMR"
        ]
    }
    
    evaluations = []
    
    for item in feature_sets.keys():
        feature_sets[item].sort()
    
    for learner in learner_names:        
        if learner == 'RGCN' or learner == 'TabNet':
            dataset = json.load(open(f'cross_validation/cross_validation_95_{learner}.json'))
            dataset_without_ohe = json.load(open(f'cross_validation/cross_validation_95_{learner}_without_ohe.json'))
            
            for key in feature_sets.keys():
                
                if key in ['Time Signal', 'Time Signal + Sentence', 'Time Signal + Sentence + Discourse']:
                    for data in dataset_without_ohe: 
                        estimator = data['estimator']
                        feature_set = list(data['feature_set'])
                        feature_set.sort()
                        
                        if estimator == learner and feature_set == feature_sets[key]:
                            evaluation = {}
                            evaluation['learner'] = (learner)
                            evaluation['feature'] = (key)
                            evaluation['precision'] = (statistics.median(data['precision_macro']))
                            evaluation['recall'] = (statistics.median(data['recall_macro']))
                            evaluation['f1'] = (statistics.median(data['f1_macro']))
                            evaluations.append(evaluation)
                else:
                    for data in dataset: 
                        estimator = data['estimator']
                        feature_set = list(data['feature_set'])
                        feature_set.sort()
                        
                        if estimator == learner and feature_set == feature_sets[key]:
                            evaluation = {}
                            evaluation['learner'] = (learner)
                            evaluation['feature'] = (key)
                            evaluation['precision'] = (statistics.median(data['precision_macro']))
                            evaluation['recall'] = (statistics.median(data['recall_macro']))
                            evaluation['f1'] = (statistics.median(data['f1_macro']))
                            evaluations.append(evaluation)
        
        else:
            dataset = json.load(open(f'cross_validation/cross_validation_95.json'))
            dataset_without_ohe = json.load(open(f'cross_validation/cross_validation_95_without_ohe.json'))
            
            for key in feature_sets.keys():
                
                if key in ['Time Signal', 'Time Signal + Sentence', 'Time Signal + Sentence + Discourse']:
                    for data in dataset_without_ohe: 
                        estimator = data['estimator']
                        feature_set = list(data['feature_set'])
                        feature_set.sort()
                        
                        if estimator == learner and feature_set == feature_sets[key]:
                            evaluation = {}
                            evaluation['learner'] = (learner)
                            evaluation['feature'] = (key)
                            evaluation['precision'] = (statistics.median(data['test_precision_macro']))
                            evaluation['recall'] = (statistics.median(data['test_recall_macro']))
                            evaluation['f1'] = (statistics.median(data['test_f1_macro']))
                            evaluations.append(evaluation)
                else:
                    for data in dataset: 
                        estimator = data['estimator']
                        feature_set = list(data['feature_set'])
                        feature_set.sort()
                        
                        if estimator == learner and feature_set == feature_sets[key]:
                            evaluation = {}
                            evaluation['learner'] = (learner)
                            evaluation['feature'] = (key)
                            evaluation['precision'] = (statistics.median(data['test_precision_macro']))
                            evaluation['recall'] = (statistics.median(data['test_recall_macro']))
                            evaluation['f1'] = (statistics.median(data['test_f1_macro']))
                            evaluations.append(evaluation)
    
    
    df = pd.DataFrame.from_dict(evaluations)
    df.drop_duplicates(inplace=True)
    df = df.round(2)
    
    print(tabulate.tabulate(df.sort_values(by=['f1'], ascending=False), headers='keys', tablefmt='latex'))    
    pass


# construct_evaluation_table_for_temporal_classifiers()

def combine_temporal_dataset():

    rr_dataset = pd.read_excel('IRR_data/temporal_relation_dataset.xlsx', sheet_name='Sheet1')[['Id', 'T1', 'T2', 'relation']]
    
    bw_dataset_p1 = pd.read_excel('IRR_data/technique_relation_dataset_BW.xlsx', sheet_name='sheet1')
    bw_dataset_p2 = pd.read_excel('IRR_data/technique_relation_dataset_BW.xlsx', sheet_name='sheet2')
    bw_dataset_p3 = pd.read_excel('IRR_data/technique_relation_dataset_QM.xlsx')
    bw_dataset = pd.concat([bw_dataset_p1, bw_dataset_p2, bw_dataset_p3])[['Id', 'T1', 'T2', 'relation']]
    
    
    # print(tabulate.tabulate(rr_dataset.head(10), headers='keys', tablefmt='psql'))
    # print(tabulate.tabulate(bw_dataset.head(10), headers='keys', tablefmt='psql'))
    
    combined_dataset = pd.concat([bw_dataset, rr_dataset])
    
    print(f'{rr_dataset.shape} | {bw_dataset.shape} | {combined_dataset.shape}')
    
    combined_dataset.drop_duplicates(inplace=True)
        
    # print(tabulate.tabulate(combined_dataset.head(10), headers='keys', tablefmt='psql'))
    
    print(f'{rr_dataset.shape} | {bw_dataset.shape} | {combined_dataset.shape}')
    
    labels = ['NEXT', 'CONCURRENT', 'OVERLAP']
    
    combined_dataset.to_excel('temporal_relation_dataset_combined.xlsx')

# combine_temporal_dataset()