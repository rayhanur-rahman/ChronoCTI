from fileinput import filename
import json
from logging import root
import re
import subprocess
import os
from bs4 import BeautifulSoup
import spacy
import benepar
import ParseTree
from tqdm import tqdm

# this program analyzes the timeML XML outputs of CTI reports and converts to json file


def convert_constituency_parsing_string_to_tree(doc):
    forest = []

    for sent in list(doc.sents):
        tree_text = sent._.parse_string
        tree_text_modified = ''

        for char in tree_text:
            if char == '(':
                tree_text_modified += '( '
            elif char == ')':
                tree_text_modified += ' )'
            else:
                tree_text_modified += char

        tree_tokens = tree_text_modified.split(' ')

        head: ParseTree.Node | None = None
        current: ParseTree.Node | None = None

        index = 0
        for idx in range(0, len(tree_tokens)):
            token = tree_tokens[idx]
            if token == '(':
                if head == None:
                    head = ParseTree.Node()
                    current = head
                else:
                    newNode = ParseTree.Node()
                    current.children.append(newNode)
                    newNode.Parent = current
                    current = newNode

            elif token == ')':
                current = current.Parent

            else:
                if tree_tokens[idx-1] == '(':
                    current.pos = token
                elif tree_tokens[idx+1] == ')':
                    current.word = token
                    current.index = index
                    index += 1
                else:
                    pass

        forest.append(head)

    root: ParseTree.Node = ParseTree.Node()
    root.children.extend(forest)
    for item in forest:
        item.Parent = root
    return root


def search(word, root, resultNodes):
    if root.word == word:
        resultNodes.append(root)
    else:
        for child in root.children:
            search(word, child, resultNodes)


def getPhraseNode(node, phraseType, phraseNode):
    current = node
    if current.pos == phraseType:
        # if current.pos in ['NP', 'VP', 'PP', 'S']:
        phraseNode.append(current)
    else:
        current = current.Parent
        getPhraseNode(current, phraseType, phraseNode)


def getPhraseText(node, ls):
    if node.word != None:
        ls.append(node.word)
    for child in node.children:
        getPhraseText(child, ls)

PATH_TO_TIMEML_OUTPUT = 'unseen_reports_timeML_outputs'
PATH_TO_TIMEML_JSON_OUTPUT = 'unseen_reports_timeML_outputs/unseen_reports_timeML_output.json'

list_of_cti_report_file_names = []
list_of_cti_report_file_names.extend(
    os.listdir(f'{PATH_TO_TIMEML_OUTPUT}'))
list_of_cti_report_file_names.sort()


# This part will be borken because if you install spacy-transformer package
nlp = spacy.load('en_core_web_lg')
nlp.add_pipe('benepar', config={'model': 'benepar_en3'})

all_json_data = []

failed_cases = 0

for idx in tqdm(range(len(list_of_cti_report_file_names))):
    file_name = list_of_cti_report_file_names[idx]

    if '.xml' not in file_name:
        continue

    with open(f'{PATH_TO_TIMEML_OUTPUT}/{file_name}') as file:
        
        raw_data = file.read()
        xml_data = BeautifulSoup(raw_data, 'xml')

        xml_sentences = xml_data.find_all('s')
        xml_lexicons = xml_data.find_all('lex')
        xml_events = xml_data.find_all('EVENT')
        xml_time_links = xml_data.find_all('TLINK')

        xml_time_links = [
            x for x in xml_time_links if 'relatedToEventInstance' in x.attrs.keys()]

        json_data = {}
        json_data['report-id'] = file_name[:-4]
        if str(json_data['report-id'])[-1] == '.':
            json_data['report-id'] = json_data['report-id'][:-1]
        json_data['sentences'] = []

        dropped_events = []

        for x_s in xml_sentences:
            # try:
            sentence = {}

            sentence['id'] = x_s.attrs['id']

            sentence_lower_bounadry = int(x_s.attrs['begin'])
            sentence_upper_bounadry = int(x_s.attrs['end'])

            sentence['words'] = [{
                'text': lex.attrs['text'],
                'begin': int(lex.attrs['begin']),
                'end': int(lex.attrs['end'])
            } for lex in xml_lexicons if int(lex.attrs['begin']) >= sentence_lower_bounadry and int(lex.attrs['end']) <= sentence_upper_bounadry]

            sentence['text'] = str(' '.join([x['text']
                                for x in sentence['words']])).strip()
            sentence['events'] = []

            ttt = sentence['text']
            # print(len(ttt))

            doc = nlp(f'{sentence["text"]}')

            root = convert_constituency_parsing_string_to_tree(doc)

            dump = []
            for ev in xml_events:
                if int(ev.attrs['begin']) >= sentence_lower_bounadry and int(ev.attrs['end']) <= sentence_upper_bounadry:
                    text = ev.attrs['form']
                    index = len([x for x in dump if x == text])
                    dump.append(text)

                    phraseType = ''
                    spacy_pos = [
                        token.pos_ for token in doc if token.text == text]

                    if len(spacy_pos) > 0:
                        if spacy_pos[0] == 'NOUN':
                            phraseType = 'NP'
                        if spacy_pos[0] == 'VERB':
                            phraseType = 'VP'

                        if phraseType != '':
                            found_nodes_in_parse_tree = []
                            search(text, root, found_nodes_in_parse_tree)
                            if len(found_nodes_in_parse_tree) != 0:
                                try:
                                    found_node_in_parse_tree = found_nodes_in_parse_tree[index]
                                    phraseNodes = []
                                    getPhraseNode(
                                        found_node_in_parse_tree, phraseType, phraseNodes)
                                    ls = []
                                    getPhraseText(phraseNodes[0], ls)
                                    phrase_text = str(' '.join(ls)).strip()

                                    sentence['events'].append({'id': ev.attrs['eiid'], 'text': ev.attrs['form'], 'epos': ev.attrs['epos'], 'class': ev.attrs['class'], 'begin': int(
                                        ev.attrs['begin']), 'end': int(ev.attrs['end']), 'index': index, 'phraseType': phraseType, 'phraseText': phrase_text})

                                except:
                                    dropped_events.append(ev.attrs['eiid'])
                                    failed_cases += 1
                        else:
                            dropped_events.append(ev.attrs['eiid'])

                    else:
                        dropped_events.append(ev.attrs['eiid'])

            json_data['sentences'].append(sentence)
            
            # except:
            #     pass

        json_data['relations'] = []

        for tlink in xml_time_links:
            e1 = tlink.attrs['eventInstanceID']
            e2 = tlink.attrs['relatedToEventInstance']
            rel = tlink.attrs['relType']

            if e1 not in dropped_events and e2 not in dropped_events:
                json_data['relations'].append({
                    'e1': e1,
                    'e2': e2,
                    'relation': rel
                })
            else:
                pass

        all_json_data.append(json_data)


json.dump(all_json_data, open(f'{PATH_TO_TIMEML_JSON_OUTPUT}', 'w'))

print('count of falied parses: ', failed_cases)
