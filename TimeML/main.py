import re
import subprocess
import os
from bs4 import BeautifulSoup
import spacy, benepar
import ParseTree

# os.system('rm out.xml; python tarsqi.py input.txt out.xml')

# with open('out.xml', 'r') as xml_file:
#     data = xml_file.read()
    
#     bs_data = BeautifulSoup(data, 'xml')
    
#     events = bs_data.find_all('EVENT')
    
#     for event in events:
#         print(event.attrs['eiid'], event.attrs['class'], event.attrs['form'], event.attrs['epos'])

    
#     time_links = bs_data.find_all('TLINK')
    
#     for tlink in time_links:
#         print(tlink.attrs['eventInstanceID'], tlink.attrs['relType'], tlink.attrs['relatedToEventInstance'])
    
#     # print(data)

nlp = spacy.load('en_core_web_lg')
nlp.add_pipe('benepar', config={'model': 'benepar_en3'})
# doc = nlp('After downloading the dll, the attackers installed several scheduled tasks')
doc = nlp('depending on the variant .')

forest = []
parse_trees = []

for sent in list(doc.sents):
    tree_text = sent._.parse_string
    parse_trees.append(tree_text)
    tree_text_modified = ''

    for char in tree_text:
        if char == '(':
            tree_text_modified += '( '
        elif char == ')':
            tree_text_modified += ' )'
        else:
            tree_text_modified += char


    tree_tokens = tree_text_modified.split(' ')

    head : ParseTree.Node | None = None
    current : ParseTree.Node | None = None


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

root : ParseTree.Node = ParseTree.Node()
root.children.extend(forest)
for item in forest: 
    item.Parent = root



def visit(root):
    print(f'> {root.word}')
    
    for child in root.children:
        visit(child)

# visit(root)

def search(word, root, resultNodes):
    if root.word == word: 
        resultNodes.append(root)
    else:
        for child in root.children:
            search(word, child, resultNodes)
        
resultNodes = []
search('used', root, resultNodes)

def getPhraseNode(node, phraseType, phraseNode):
    current = node
    if current.pos == phraseType:
        print('found phrase')
        phraseNode.append(current)
    else:
        current = current.Parent
        getPhraseNode(current, phraseType, phraseNode)

phraseNodes = []

for node in resultNodes:
    phraseNode = []
    getPhraseNode(node, 'VP', phraseNode)
    phraseNodes.append(phraseNode)
    
print(phraseNodes)

def getPhraseText(node, ls):
    if node.word != None:
        ls.append(node.word)
    for child in node.children:
        getPhraseText(child, ls)

ls_all = []
for node in phraseNodes:
    ls = []
    getPhraseText(node[0], ls)
    ls_all.append(ls)

phrase_texts = [ str(' '.join(x)).strip() for x in ls_all]
    
xxx = 0

# (S (PP (IN After) (S (VP (VBG downloading) (NP (DT the) (NN dll))))) (, ,) (NP (DT the) (NNS attackers)) (VP (VBD installed) (NP (JJ several) (VBN scheduled) (NNS tasks))))

# print(sent._.labels)
# # ('S',)
# print(list(sent._.children)[0])




