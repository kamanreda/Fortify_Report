import zipfile


def unzip_fpr(path):
    with zipfile.ZipFile(path, 'r') as zfile:
        zfile.namelist()
        zfile.extract('audit.fvdl', './fpr')
        zfile.extract('audit.xml', './fpr')


if __name__ == '__main__':
    unzip_fpr('./test.fpr')