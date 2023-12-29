import logging

from simpletransformers.language_modeling import (
    LanguageModelingModel,
    LanguageModelingArgs,
)


logging.basicConfig(level=logging.INFO)
transformers_logger = logging.getLogger("transformers")
transformers_logger.setLevel(logging.WARNING)

batch_size = [8, 32, 64]

for item in batch_size:
    
    print(f'training for batch size: {item}')
    
    model_args = LanguageModelingArgs()
    model_args.reprocess_input_data = True
    model_args.overwrite_output_dir = True
    model_args.num_train_epochs = 1
    model_args.dataset_type = "simple"
    model_args.use_multiprocessing = True
    model_args.dataloader_num_workers = 8
    model_args.process_count = 8
    model_args.use_multiprocessing_for_evaluation = True
    model_args.use_cuda = True
    model_args.overwrite_output_dir = True
    model_args.sliding_window = True
    model_args.train_batch_size = item
    model_args.eval_batch_size = item
    model_args.output_dir = f'CTI-Roberta/outputs_{item}/'
    model_args.best_model_dir = f'CTI-Roberta/outputs_{item}/model-best'
    model_args.save_steps = -1

    train_file = "train.txt"
    test_file = "test.txt"

    model = LanguageModelingModel(
        "roberta", "roberta-base", args=model_args, use_cuda = True
    )

    # Train the model
    model.train_model(train_file, eval_file=test_file)

    # Evaluate the model
    result = model.eval_model(test_file)