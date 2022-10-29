from lxml import etree


class Audit_parser:
    def __init__(self, audit_xml, audit_namespace):
        self.audit_xml = audit_xml
        self.audit_namespace = audit_namespace
        parser = etree.XMLParser(encoding="utf-8")
        self.root = etree.parse(audit_xml, parser=parser)
        self.instanceIds = []

    def Exploitable(self):
        self.instanceIds = self.root.xpath('./ns2:IssueList/ns2:Issue/ns2:Tag/ns2:Value[text()="Exploitable"]/../../@instanceId', namespaces=self.audit_namespace)
        return self.instanceIds
