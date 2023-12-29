from typing import List
from xmlrpc.client import Boolean
from mitreattack.stix20 import MitreAttackData
import utils
class Tactic:
    def __init__(self, id : str, name : str):
        self.id : str = id
        self.name : str = name
        self.techniques : List['Technique'] = []
        self.sequence : int
        self.stixObject = None

class Technique:
    def __init__(self, id : str, name : str):
        self.id : str = id
        self.name : str = name
        self.tactics = []
        self.description = ''
        self.stixObject = None
        self.attackPatternId = None
        self.groups = []
        self.softwares = []
        self.procedures = []
        self.vector = []
        self.parentId = ''
        self.isSubTechnique: Boolean

class Group:
    def __init__(self, id):
        self.id = id
        self.name = ''
        self.techniques = []
        self.aliases = []

class Software:
    def __init__(self, id):
        self.id = id
        self.name = ''
        self.techniques = []
        self.aliases = []

class Procedure:
    def __init__(self, id):
        self.id = id
        self.technique : 'Technique'
        self.parentTechnique : 'Technique'
        self.usedBy : 'Group' | 'Software'
        self.description = ''
        self.text = ''
        self.vector = []
        self.urls = []

class Dataset:
    def __init__(self) -> None:
        self.techniques : List['Technique'] = []
        self.tactics : List['Tactic'] = []
        self.groups : List['Group'] = []
        self.softwares : List['Software'] = []
        self.procedures : List['Procedure'] = []
        self.attackInstances : List[List['Technique']] = []
        self.buildDataset()
    
    def buildDataset(self):
        mitre_attack_data = MitreAttackData("data/enterprise-attack-12.1.json")
        
        groupsObject = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
        for item in groupsObject:
            group = Group(item['external_references'][0]['external_id'])
            group.name = item['name']
            if 'aliases' in item.keys():
                group.aliases.extend(item['aliases'])
            self.groups.append(group)

        softwaresObject = mitre_attack_data.get_software(remove_revoked_deprecated=True)
        for item in softwaresObject:
            software = Software(item['external_references'][0]['external_id'])
            software.name = item['name']
            if 'aliases' in item.keys(): 
                software.aliases.extend(item['aliases'])
            self.softwares.append(software)


        tacticsObject = mitre_attack_data.get_tactics(remove_revoked_deprecated=True)
        for item in tacticsObject:
            tactic = Tactic(item['external_references'][0]['external_id'], item['name'])
            tactic.stixObject = item
            self.tactics.append(tactic)

        techniquesObject = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
        for item in techniquesObject:
            technique = Technique(item['external_references'][0]['external_id'], item['name'] )
            technique.attackPatternId = item['id']

            tacticIdDict = {
                'reconnaissance': 'TA0043',
                'resource-development': 'TA0042',
                'initial-access': 'TA0001',
                'execution': 'TA0002',
                'persistence': 'TA0003',
                'privilege-escalation': 'TA0004',
                'defense-evasion': 'TA0005',
                'credential-access': 'TA0006',
                'discovery': 'TA0007',
                'lateral-movement': 'TA0008',
                'collection': 'TA0009',
                'command-and-control': 'TA0011',
                'exfiltration': 'TA0010',
                'impact': 'TA0040',
            }
            for phase in item['kill_chain_phases']:
                ta = next( ( x for x in self.tactics if x.id == tacticIdDict[f'{phase["phase_name"]}']), None )
                if ta != None:
                    technique.tactics.append(ta)
                    ta.techniques.append(technique)

            technique.stixObject = item
            technique.description = item['description']

            self.techniques.append(technique)

            groupsUsingThisTechnique = mitre_attack_data.get_groups_using_technique(technique.attackPatternId)
            softwaresUsingThisTechnique = mitre_attack_data.get_software_using_technique(technique.attackPatternId)
            x = 0

            for groupItem in groupsUsingThisTechnique:
                group = next( (x for x in self.groups if x.id == groupItem['object']['external_references'][0]['external_id']), None )
                if group != None:
                    group.techniques.append(technique)
                    technique.groups.append(group)

                    proc = Procedure(f'{group.id}:{technique.id}')
                    proc.technique = technique
                    proc.usedBy = group
                    proc.text = groupItem['relationship']['description']
                    proc.description = utils.cleanProcedureText(proc.text)
                    proc.text = utils.cleanProcedureText2(proc.text)
                    
                    if 'relationship' in groupItem.keys() and 'external_references' in groupItem['relationship'].keys():
                        for eitem in groupItem['relationship']['external_references']:
                            proc.urls.append({
                                'name': eitem['source_name'],
                                'description': eitem['description'],
                                'url': eitem['url']
                            })
                    
                    technique.procedures.append(proc)
                    self.procedures.append(proc)

            for softwareItem in softwaresUsingThisTechnique:
                software = next( (x for x in self.softwares if x.id == softwareItem['object']['external_references'][0]['external_id']), None )
                if software != None:
                    software.techniques.append(technique)
                    technique.softwares.append(software)

                    proc = Procedure(f'{software.id}:{technique.id}')
                    proc.technique = technique
                    proc.usedBy = software
                    
                    proc.text = softwareItem['relationship']['description']
                    proc.description = utils.cleanProcedureText(proc.text)
                    proc.text = utils.cleanProcedureText2(proc.text)
                    
                    if 'relationship' in softwareItem.keys() and 'external_references' in softwareItem['relationship'].keys():
                        for eitem in softwareItem['relationship']['external_references']:
                            proc.urls.append({
                                'name': eitem['source_name'],
                                'description': eitem['description'],
                                'url': eitem['url']
                            })
                    
                    technique.procedures.append(proc)
                    self.procedures.append(proc)

        for te in self.techniques:
            if len(te.id) == 9:
                parentId = te.id[0:5]
                te.parentId = parentId
                te.isSubTechnique = True
            else:
                te.parentId = te.id
                te.isSubTechnique = False
        
        for proc in self.procedures:
            proc.parentTechnique = [x for x in self.techniques if x.id == proc.technique.parentId and x.isSubTechnique == False][0]
        
        for item in self.groups:
            tes = [x.parentId for x in item.techniques]
            tes = list(set(tes))
            self.attackInstances.append(tes)

        for item in self.softwares:
            tes = [x.parentId for x in item.techniques]
            tes = list(set(tes))
            self.attackInstances.append(tes)



class Prediction:
    def __init__(self, id) -> None:
        self.id = id
        self.procedure: str
        self.default: str
        self.others = []