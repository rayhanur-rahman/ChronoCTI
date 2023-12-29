import spacy
from spacy import displacy
import subprocess
import os, shutil


def purge():
    modelNames = ['w2vAll', 'lgAll', 'trfAll', 'robertaBaseAll', 'robertaCtiAll']

    for i in range(0, 50):
        entries = os.listdir('bagging_models/')
        
        for entry in entries:
            for model in modelNames:
                if f'{model}-{i}' == entry:
                    path = os.path.abspath("bagging_models")
                    src = f'{path}/{entry}/metric.json'
                    dst = f'{path}/dump/metric-{model}-{i}.json'
                    shutil.copy2(src, dst)
                    src = f'{path}/{entry}/model-best/meta.json'
                    dst = f'{path}/dump/meta-{model}-{i}.json'
                    shutil.copy2(src, dst)
                    
                    try:
                        shutil.rmtree(f'{path}/{model}-{i}')
                    except OSError as e:
                        print(f'Error: {path}/{model}-{i} : {e.strerror}')


# spacy project run all . --vars.train bootstrap_samples/training-1.jsonl --vars.dev bootstrap_samples/eval-0.jsonl --vars.output bm0

for i in range(5):
    result = subprocess.run(['spacy', 'project', 'run', 'all', '.', "--vars.train", f"train_test_splits/train_selected120_split_{i}.jsonl", "--vars.dev", f"train_test_splits/test_selected120_split_{i}.jsonl", "--vars.output", f"w2vAll-{i}", "--vars.config", f"config-w2v.cfg"]) 
    print(result.stdout)
    purge()

    result = subprocess.run(['spacy', 'project', 'run', 'all', '.', "--vars.train", f"train_test_splits/train_selected120_split_{i}.jsonl", "--vars.dev", f"train_test_splits/test_selected120_split_{i}.jsonl", "--vars.output", f"lgAll-{i}", "--vars.config", f"config-lg.cfg"]) 
    print(result.stdout)
    purge()

    result = subprocess.run(['spacy', 'project', 'run', 'all', '.', "--vars.train", f"train_test_splits/train_selected120_split_{i}.jsonl", "--vars.dev", f"train_test_splits/test_selected120_split_{i}.jsonl", "--vars.output", f"trfAll-{i}", "--vars.config", f"config-trf.cfg"]) 
    print(result.stdout)
    purge()
        
    result = subprocess.run(['spacy', 'project', 'run', 'all', '.', "--vars.train", f"train_test_splits/train_selected120_split_{i}.jsonl", "--vars.dev", f"train_test_splits/test_selected120_split_{i}.jsonl", "--vars.output", f"robertaBaseAll-{i}", "--vars.config", f"config-roberta-base.cfg"]) 
    print(result.stdout)
    purge()

    result = subprocess.run(['spacy', 'project', 'run', 'all', '.', "--vars.train", f"train_test_splits/train_selected120_split_{i}.jsonl", "--vars.dev", f"train_test_splits/test_selected120_split_{i}.jsonl", "--vars.output", f"robertaCtiAll-{i}", "--vars.config", f"config-roberta-cti.cfg"]) 
    print(result.stdout)
    purge()
