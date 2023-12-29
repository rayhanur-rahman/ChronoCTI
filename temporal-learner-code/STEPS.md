# Do the following
- run `compare_ttp_classifiers.py` for comparing lg, trf, w2v, roberta, and custom roberta models
- run `prepareDiscourseDataset.py` to convert report to a json file containing sentences and line numbers
- run `classify_sentences_to_TTPs.py` to classify TTPs of all sentences in a report
- run `evaluate_ttps_classification_per_report.py` for evaluating the TTPs classification performance per report
- run `classify_next_sentence.py` for classifying the relation of consecutive sentences
- run `TTPsToGraphCoref/construct_dataset_of_coreferred_sentences.py` to generate coref sentence dataset
- run `classify_next_sentence_coref.py` for classifying the relation of consecutive coreferenced sentences
- run `construct_features_from_next_discourse_relation.py` for constructing TTPs-pairwise relations for next sentence discourse relation
- run `construct_features_from_next_discourse_relation_coref.py` for constructing TTPs-pairwise relations for coreferencing sentence discourse relation
- run `construct_consecutive_sentence_features.py`
- run `construct_coref_sentence_features.py`
- run `construct_similarity_features.py`
- run `construct_time_signal_heuristics.pyj`
- run `combine_all_features.py`
- run `make_final_evaluation.py`, `cross_validate_p2.py`, `learn_graph_ML_imbalanced_multilabel-v2.py`

