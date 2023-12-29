def calculate_precision(predicted, actual):
    P = set(predicted)
    A = set(actual)
    if len(P) > 0:
        return round(100 * len(A.intersection(P)) / len(P), 2)
    else:
        return 0


def calculate_recall(predicted, actual):
    P = set(predicted)
    A = set(actual)
    if len(A) > 0:
        return round(100 * len(A.intersection(P)) / len(A), 2)
    else:
        return 0

def calculate_f_score(precision, recall, beta):
    if ( beta * beta * precision) + recall > 0: return round((1 + beta * beta) * (precision * recall) / ( ( beta * beta * precision) + recall), 2)
    else: return 0
    
def calculate_label_cardinality(dataset):
    numOfExmples = len(dataset.keys())
    numOfAllLabels = 0
    
    for key in dataset.keys():
        numOfAllLabels += len(set(dataset[key]))
    
    return numOfAllLabels/numOfExmples

def calculate_label_density(dataset, labels):
    allLabels = []
    
    for key in dataset.keys():
        allLabels.extend(dataset[key])
    
    uniqueLabelCounts = len(labels)
    
    densityPerExamples = []
    for key in dataset.keys():
        densityPerExamples.append(len(set(dataset[key])) / uniqueLabelCounts)
    
    if len(densityPerExamples) > 0: return sum(densityPerExamples) / len(densityPerExamples)
    else: return 0
    
def calculate_hamming_loss(predicted, actual, labels):
    P = set(predicted)
    A = set(actual)
    L = set(labels)
    
    NA = L.difference(A)
    NP = L.difference(P)
    
    FP = P.intersection(NA)
    FN = A.intersection(NP)
    
    return (len(FP) + len(FN)) / len(labels)

def calculate_jaccard_index(predicted, actual):
    P = set(predicted)
    A = set(actual)    
    if len(P.union(A)) > 0: return (len(A.intersection(P)))/(len(P.union(A)))
    else: return 0

def calculate_exact_match(predicted, actual):
    P = set(predicted)
    A = set(actual)    
    if len(P.intersection(A)) == len(A) and len(P) == len(A): return 1
    else: return 0
