import jsonlines
import spacy
import subprocess
import sys

from gensim.models.word2vec import Word2Vec
from gensim.models.phrases import Phrases, Phraser
from collections import defaultdict

nlp = spacy.load("en_core_web_lg")
sentences = []

# these three files contains all sentences from all reports contained in att&*ck v12.1, mitre tram dataset, and procedure sentences

with jsonlines.open('Datasets/relevance_train.jsonl') as reader:
    for data in reader:
        sentences.append(data['text'])
with jsonlines.open('Datasets/relevance_eval.jsonl') as reader:
    for data in reader:
        sentences.append(data['text'])
with jsonlines.open('Datasets/all_report_sentences.jsonl') as reader:
    for data in reader:
        sentences.append(data['text'])


tokenizedSentences = []

for text in sentences:
    words = text.split()
    words = [w for w in words if w not in nlp.Defaults.stop_words]
    tokenizedSentences.append(words)


def create_wordvecs(corpus, model_name):

    
    print (len(corpus))
    

    phrases = Phrases(corpus, min_count=30, progress_per=10000)
    print ("Made Phrases")
    
    bigram = Phraser(phrases)
    print ("Made Bigrams")
    
    sentences = phrases[corpus]
    print ("Found sentences")
    word_freq = defaultdict(int)

    for sent in sentences:
        for i in sent:
            word_freq[i]+=1

    print (len(word_freq))
    
    print ("Training model now...")
    w2v_model = Word2Vec(min_count=5,
                        window=5,
                        vector_size=300,
                        sample=6e-5,
                        alpha=0.03,
                        min_alpha=0.0007, workers=8,
                        negative=20)
    w2v_model.build_vocab(sentences, progress_per=10000)
    w2v_model.train(sentences, total_examples=w2v_model.corpus_count, epochs=30, report_delay=1)
    w2v_model.wv.save_word2vec_format(f"{model_name}")
    w2v_model.save(f'Datasets/{model_name}.bin')
    w2v_model.wv.save_word2vec_format(f"Datasets/{model_name}.txt")


create_wordvecs(tokenizedSentences, "w2v_cti_reports-v2")


# this will create a custom word2vec model named 'cti_w2v
def load_word_vectors(model_name, word_vectors):
    # pipenv run python -m spacy init vectors en Datasets/w2v_cti_reports-v2.txt Datasets/cti_w2v_v2
    subprocess.run([sys.executable,
                    "-m",
                    "spacy",
                    "init",
                    "vectors",
                    "en",
                    word_vectors,
                    model_name]
                    )
    print (f"New spaCy model created with word vectors. File: {model_name}")

load_word_vectors("Datasets/cti_w2v_v2", "Datasets/w2v_cti_reports-v2.txt")