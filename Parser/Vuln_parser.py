from lxml import etree


class Vuln_parser:
    def __init__(self, audit_fvdl, fvdl_namespace, instanceIds):
        self.audit_fvdl = audit_fvdl
        self.fvdl_namespace = fvdl_namespace
        self.instanceIds = instanceIds
        parser = etree.XMLParser(encoding="utf-8")
        self.root = etree.parse(audit_fvdl, parser=parser)
        self.Vulnerabilities = []
        self.VulnType_dict = {}


    def getVuln(self):
        for i in self.instanceIds:
            Vuln = self.root.xpath(
                './/fvdl:Vulnerabilities/fvdl:Vulnerability/fvdl:InstanceInfo/fvdl:InstanceID[text()=$val]/../..',
                val=i,
                namespaces=self.fvdl_namespace)
            self.Vulnerabilities.append(Vuln[0])
        return self.Vulnerabilities


    def getVulnType(self):
        VulnType_list = []
        for vuln in self.Vulnerabilities:
            if (vuln.xpath('./fvdl:ClassInfo/fvdl:Subtype/text()', namespaces=self.fvdl_namespace)):
                list_tmp = ''.join(
                    vuln.xpath('./fvdl:ClassInfo/fvdl:Type/text()', namespaces=self.fvdl_namespace)) + '-' + ''.join(
                    vuln.xpath('./fvdl:ClassInfo/fvdl:Subtype/text()', namespaces=self.fvdl_namespace))
            else:
                list_tmp = ''.join(vuln.xpath('./fvdl:ClassInfo/fvdl:Type/text()', namespaces=self.fvdl_namespace))
            if list_tmp in VulnType_list:
                continue
            else:
                VulnType_list.append(list_tmp)
        for i in VulnType_list:
            self.VulnType_dict[i] = []
        return self.VulnType_dict


    def getSinkFile(self, Vulnerability):
        Sink = Vulnerability.xpath('.//fvdl:FunctionDeclarationSourceLocation/@path',
                                   namespaces=self.fvdl_namespace)
        keylist = Vulnerability.xpath('.//fvdl:Def/@key', namespaces=self.fvdl_namespace)
        if "SinkLocation.line" in keylist:
            if not Sink:
                Sink = Vulnerability.xpath('.//fvdl:Def[@key="SinkLocation.file"]/@value',
                                           namespaces=self.fvdl_namespace)
            Sink_line = Vulnerability.xpath('.//fvdl:Def[@key="SinkLocation.line"]/@value',
                                            namespaces=self.fvdl_namespace)
        else:
            if not Sink:
                Sink = Vulnerability.xpath('.//fvdl:Def[@key="PrimaryLocation.file"]/@value',
                                           namespaces=self.fvdl_namespace)
            Sink_line = Vulnerability.xpath('.//fvdl:Def[@key="PrimaryLocation.line"]/@value',
                                            namespaces=self.fvdl_namespace)
        title = '#'.join(Sink + Sink_line)
        return title


    def parser_trace(self, trace, Trace_List):
        Entrys = trace.xpath('.//fvdl:Entry', namespaces=self.fvdl_namespace)
        for Entry in Entrys:
            SourceLocation = []
            Action = []
            Line = []
            if Entry.xpath('./fvdl:NodeRef', namespaces=self.fvdl_namespace):
                id = Entry.xpath('./fvdl:NodeRef/@id', namespaces=self.fvdl_namespace)
                Node = self.root.xpath('./fvdl:UnifiedNodePool/fvdl:Node[@id=$val]', val=id[0],
                                       namespaces=self.fvdl_namespace)
                SourceLocation = Node[0].xpath('.//fvdl:SourceLocation/@path', namespaces=self.fvdl_namespace)
                Line = Node[0].xpath('.//fvdl:SourceLocation/@line', namespaces=self.fvdl_namespace)
                Line[0] += '行'
                Action = Node[0].xpath('.//fvdl:Action/text()', namespaces=self.fvdl_namespace)
                Trace_List.append('#'.join(SourceLocation + Line + Action))
            else:
                SourceLocation = Entry.xpath('.//fvdl:SourceLocation/@path', namespaces=self.fvdl_namespace)
                Line = Entry.xpath('.//fvdl:SourceLocation/@line', namespaces=self.fvdl_namespace)
                Line[0] += '行'
                Action = Entry.xpath('.//fvdl:Action/text()', namespaces=self.fvdl_namespace)
                Trace_List.append('#'.join(SourceLocation + Line + Action))
                if Entry.xpath('.//fvdl:Reason/fvdl:TraceRef', namespaces=self.fvdl_namespace):
                    TraceRef_id = Entry.xpath('.//fvdl:Reason/fvdl:TraceRef/@id', namespaces=self.fvdl_namespace)
                    TraceRef = self.root.xpath('./fvdl:UnifiedTracePool/fvdl:Trace[@id=$val]', val=TraceRef_id[0],
                                               namespaces=self.fvdl_namespace)
                    self.parser_trace(TraceRef[0],Trace_List)
        return Trace_List


    def sort_dict(self):
        for key in self.VulnType_dict.keys():
            self.VulnType_dict[key].sort(key=self.takeFirst)


    def takeFirst(self, elem) -> tuple:
        try:
            a, b = elem[0].split('#')
            return (a, int(b))
        except ValueError as e:
            print('发生错误，漏洞title丢失：' + str(e))
            print('错误漏洞为：')
            print(elem)


    def start(self):
        self.getVuln()
        self.getVulnType()
        for Vulnerability in self.Vulnerabilities:
            Vuln_Trace = []
            title = self.getSinkFile(Vulnerability)
            Traces = Vulnerability.xpath('.//fvdl:Trace', namespaces=self.fvdl_namespace)
            for Trace in Traces:
                Trace_List = []
                Trace_List = self.parser_trace(Trace, Trace_List)
                Vuln_Trace.append(Trace_List)
            Vuln_Trace.insert(0, title)

            if (Vulnerability.xpath('./fvdl:ClassInfo/fvdl:Subtype/text()', namespaces=self.fvdl_namespace)):
                type = ''.join(
                    Vulnerability.xpath('./fvdl:ClassInfo/fvdl:Type/text()', namespaces=self.fvdl_namespace)) + '-' + ''.join(
                    Vulnerability.xpath('./fvdl:ClassInfo/fvdl:Subtype/text()', namespaces=self.fvdl_namespace))
            else:
                type = ''.join(Vulnerability.xpath('./fvdl:ClassInfo/fvdl:Type/text()', namespaces=self.fvdl_namespace))

            self.VulnType_dict[type].append(Vuln_Trace)
        self.sort_dict()
        return self.VulnType_dict