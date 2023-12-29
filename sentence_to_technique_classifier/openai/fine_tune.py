
import statistics
import openai
import os
import jsonlines
import json
import re
import tqdm
from sklearn.metrics import classification_report

def create_promptv2_from_dataset(dataset_path, prompt_path):
    examples = []
    with jsonlines.open(dataset_path) as reader:
        for data in reader:
            text = data['text']
            labels = [key for key in data['cats'].keys() if data['cats']
                    [key] == 1.0]
            labels = ','.join(labels)
            examples.append({
                'messages': [
                    {"role": "user", "content": text},
                    {"role": "assistant", "content": labels}
                ]
            })

    with jsonlines.open(prompt_path, 'w') as writer:
        writer.write_all(examples)

for i in range(0, 5):
    create_promptv2_from_dataset(f'../assets/train_test_splits/train_selected120_split_{i}.jsonl', f'../assets/train_test_prompt_splits/train_selected120_promptv2_split_{i}.jsonl')
    create_promptv2_from_dataset(f'../assets/train_test_splits/test_selected120_split_{i}.jsonl', f'../assets/train_test_prompt_splits/test_selected120_promptv2_split_{i}.jsonl')


openai.api_key = os.getenv("OPENAI_API_KEY")

def eval(i, id):
    responses = []
    c = 0
    with jsonlines.open(f'../assets/train_test_splits/test_selected120_split_{i}.jsonl') as reader:
        for data in tqdm.tqdm(reader, total=2776):
            try:

                # if c == 5: break

                text = data['text']

                completion = openai.ChatCompletion.create(
                    # model="ft:gpt-3.5-turbo-0613:nc-state-university::8AU2XcCy", # Epoch = 3
                    # model="ft:gpt-3.5-turbo-0613:nc-state-university::8EnTal5X", # Epoch = 6
                    # model = "ft:gpt-3.5-turbo-1106:nc-state-university::8LbbHeKZ", # cv = 0
                    model = id, # cv = 1
                    messages=[
                        {"role": "user", "content": text}
                    ]
                )

                answer = completion.choices[0].message.content
                pattern = "T[\d]{4}"
                matches = re.findall(pattern, answer)

                responses.append({
                    "text": text,
                    "actual": [key for key in data['cats'].keys() if data['cats'][key] == 1.0],
                    "predicted": matches
                })
                c += 1
            except:
                with jsonlines.open(f'../assets/train_test_response_splits/train_test_response_splits_{i}.jsonl', 'w') as writer:
                    writer.write_all(responses)

    with jsonlines.open(f'../assets/train_test_response_splits/train_test_response_splits_{i}.jsonl', 'w') as writer:
        writer.write_all(responses)

eval(0, 'ft:gpt-3.5-turbo-1106:nc-state-university::8LbbHeKZ')
eval(1, 'ft:gpt-3.5-turbo-1106:nc-state-university::8Le7Y5gz')
eval(2, 'ft:gpt-3.5-turbo-1106:nc-state-university::8LgIxovX')
eval(3, 'ft:gpt-3.5-turbo-1106:nc-state-university::8LgLnb9f')
eval(4, 'ft:gpt-3.5-turbo-1106:nc-state-university::8LftERJZ')

def compute_confusion_report(i):

    selectedTechniques = []
    file = open('../selected_techniquesWName.json', 'r')
    selectedTechniques = json.load(file)

    selectedTechniques_namesOnly = [x['id'] for x in selectedTechniques]
    selectedTechniques_namesOnly.sort()

    y_truth = []
    y_predicted = []


    with jsonlines.open(f'../assets/train_test_response_splits/train_test_response_splits_{i}.jsonl') as reader:
        for data in tqdm.tqdm(reader, total=2776):
            actual = data['actual']
            predicted = data['predicted']

            y, y_hat = [], []
            
            for te in selectedTechniques_namesOnly:
                if te in actual:
                    y.append(1)
                else:
                    y.append(0)
                
                if te in predicted:
                    y_hat.append(1)
                else:
                    y_hat.append(0)
                
            y_truth.append(y)
            y_predicted.append(y_hat)

    out = classification_report(y_truth, y_predicted, target_names=selectedTechniques_namesOnly, zero_division=0, output_dict=True)
    
    return out['macro avg']['f1-score']


scores = []

for idx in range(5):
    score = compute_confusion_report(idx)
    scores.append(score)

print(f'{statistics.mean(scores)} | {statistics.median(scores)} | {statistics.stdev(scores)}')

losses = [0.2376, 0.1574, 0.2983, 0.1909, 0.1536]
print(f'{statistics.mean(losses)} | {statistics.median(losses)} | {statistics.stdev(losses)}')