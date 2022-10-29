import argparse
from Export.GenerateReport import GenerateReport
from Parser.Audit_parser import Audit_parser
from Parser.Vuln_parser import Vuln_parser
from Parser.fpr_parser import unzip_fpr

if __name__ == '__main__':
    # 默认配置
    audit_namespace = {'ns2': 'xmlns://www.fortify.com/schema/audit'}
    fvdl_namespace = {'fvdl': 'xmlns://www.fortifysoftware.com/schema/fvdl'}
    audit_fvdl = './fpr/audit.fvdl'
    audit_xml = './fpr/audit.xml'

    # 解析参数
    parse = argparse.ArgumentParser(description='解析fpr文件，提取漏洞调用路径')
    parse.add_argument('-p', '--path', type=str, help='输入fpr文件路径')
    parse.add_argument('-fp', '--fvdlpath', type=str, help='输入audit.fvdl文件路径')
    parse.add_argument('-xp', '--xmlpath', type=str, help='输入audit.xml文件路径')
    args = parse.parse_args()
    if args.path:
        unzip_fpr(args.path)
    else:
        audit_fvdl = args.fvdlpath
        audit_xml = args.xmlpath

    # 解析audit.xml文件
    Audit = Audit_parser(audit_xml, audit_namespace)
    instanceIds = Audit.Exploitable()
    # 解析audit.fvdl文件
    Vuln = Vuln_parser(audit_fvdl, fvdl_namespace, instanceIds)
    Vuln_dict = Vuln.start()
    # 生成报告
    Report = GenerateReport(Vuln_dict)
    Report.start()

