from simpletransformers.classification import (
    ClassificationModel, ClassificationArgs
)
import pandas as pd
import logging
import os
from sklearn.model_selection import train_test_split
import json
import sklearn
import sklearn.metrics

os.environ["TOKENIZERS_PARALLELISM"] = "false"




file = open('discourse_train_v2.json', 'r')
# file = open('discourse_train_v2_coref.json', 'r') # to train discourse coref classifier
data = json.load(file)
file.close()

uniquelabels = list(set([d['relation'] for d in data]))
print(uniquelabels)
uniquelabels.sort()
labelCount = len(uniquelabels)

text_a = [dt['S1'] for dt in data]
text_b = [dt['S2'] for dt in data]
labels = [uniquelabels.index(dt['relation']) for dt in data]

print(uniquelabels)

data_df = pd.DataFrame({
    'text_a': text_a,
    'text_b': text_b,
    'labels': labels
})

print(data_df.shape)

train_df, eval_df = train_test_split(data_df, test_size=0.20)

print(len(train_df))

# Optional model configuration
model_args = ClassificationArgs(num_train_epochs=100)
model_args.use_multiprocessing = False
model_args.dataloader_num_workers = 0
model_args.process_count = 1
model_args.use_multiprocessing_for_evaluation = False
model_args.overwrite_output_dir = True
model_args.sliding_window = False
model_args.max_seq_length = 512
model_args.train_batch_size = 16

model_args.save_steps = -1
model_args.save_model_every_epoch = False
model_args.save_eval_checkpoints = False
model_args.save_optimizer_and_scheduler = False

model_args.use_early_stopping = True
model_args.early_stopping_consider_epochs = False
model_args.early_stopping_delta = 0.01
model_args.early_stopping_metric = 'mcc'
model_args.early_stopping_metric_minimize = False
model_args.early_stopping_patience = 5

model_args.evaluate_during_training = True
model_args.evaluate_during_training_steps = 2500
model_args.evaluate_during_training_verbose = True

model_args.eval_batch_size = 16

# Create a ClassificationModel
model = ClassificationModel("roberta", "CTI-ROBERTA", use_cuda=False, args = model_args, num_labels=labelCount)
# model = ClassificationModel("roberta", "roberta-base", use_cuda=False, args = model_args, num_labels=labelCount)
# model = ClassificationModel("roberta", "mlm", use_cuda=False, args = model_args, num_labels=3)
# model = ClassificationModel("roberta", "outputs", use_cuda=False, args = model_args, num_labels=3)


# Train the model
model.train_model(train_df, eval_df=eval_df)

# Evaluate the model
result, model_outputs, wrong_predictions = model.eval_model(
    eval_df
)

x = 0

y_true = eval_df['labels'].tolist()
y_pred = [  arr.tolist().index(max(arr.tolist())) for arr in model_outputs]
print('weighted:', sklearn.metrics.f1_score(y_true, y_pred, average='weighted'))
print('macro:', sklearn.metrics.f1_score(y_true, y_pred, average='macro'))
print('micro:', sklearn.metrics.f1_score(y_true, y_pred, average='micro'))
print(sklearn.metrics.classification_report(y_true, y_pred, target_names = uniquelabels))
