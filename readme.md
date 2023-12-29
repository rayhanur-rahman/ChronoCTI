# ChronoCTI
ChronoCTI is an NLP+ML pipeline for identifying temporal patterns of cyberattack TTPs. This repository primarily contains the source code for building the pipeline. This repository does not contain the intermediate outputs, and the final model takes approximately 250GB of disk space. Please contact the owner by creating an issue if you want access. 

# steps for building ChronoCTI
- install `pipenv`
- run `pipenv install`
- run `pipenv shell`
- run `python -m spacy download en_core_web_lg`
- run `create_cti_w2v.py`
- go to `roberta-cti and discourse classifier`
- run `pipenv install`
- run `mlm.py`. This will train the Roberta-CTI model. Copy the `output 16` folder's content, and place it as `Roberta-CTI` folder. 
- run `train_discourse_relation.py`. This will train discourse relation classifier for next sentences. 
- run `train_discourse_relation_coref.py`. This will train discourse relation classifier for coreferenced sentences. 
- go to `sentence_to_technique_classifier`
- run `pipenv install`. if you have a gpu, go to `Pipfile`, and uncomment `cupy`
- set your openai key as env var: `OPENAI_API_KEY`
- copy `Datasets/cti-w2v_v2` to `cti_w2v_v2`
- copy `Roberta-CTI` from the `roberta-cti and discourse classifier`, and place the folder in the root directory of `sentence_to_technique_classifier`
- run `train_models.py` and `openapi/fine_tune.py`. This will create learners for classifying sentences to att&ck techniques
- get timeML features
  - to do this, go to `TimeML`
  - go to the `TimeML` directory. This directory contains the `tarsqi-ttk` source code, with our added files. You can go to [tarsqi-ttk dicumentation](https://tarsqi.github.io/ttk/versions/3.0.1/index.html) to know more to install `tarsqi-ttk` properly depending on your system
  - run `pip install`
  - follow the direction provided in `STEPS.md` 
- get apriori features
  - go to `apriori-features`
    - run `pip install`
    - follow the instructions in `STEPS.md q`
- get coreference features
  - go to `neuralcoref`
- go to `temporal-learner-code`
  - follow the methods in `STEPS.md`

