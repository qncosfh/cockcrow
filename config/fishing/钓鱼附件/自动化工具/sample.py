

import os
import zipfile
import re
import sys
import shutil
# 解压
def unZipFile(dirpath):
    zFile = zipfile.ZipFile(dirpath, mode="r")
    zFile.extractall("./test")
    zFile.close()


# 替换url
def replaceFile(dirpath, url):
    with open(dirpath, "r",encoding="utf-8")as f:
        #content = f.read()
        #print(content)

        content=""
        for line in f:
            replaceText=re.sub('(?<=Target=").*?(?=")', url, line)
            content+=replaceText
        #f.seek(0)
        #f.truncate()
       # f.write(content)
        f.close()
        os.remove(dirpath)
        with open(dirpath, "w+", encoding="utf-8") as f:
            f.write(content)
        f.close()


# 压缩打包
def zipDir(dirpath, outFullName):
    """
    压缩指定文件夹
    :param dirpath: 目标文件夹路径
    :param outFullName: 压缩文件保存路径+xxxx.zip
    :return: 无
    """
    zip = zipfile.ZipFile(outFullName, "w", zipfile.ZIP_DEFLATED)
    for path, dirnames, filenames in os.walk(dirpath):
        # 去掉目标跟路径，只对目标文件夹下边的文件及文件夹进行压缩
        fpath = path.replace(dirpath, '')

        for filename in filenames:
            zip.write(os.path.join(path, filename), os.path.join(fpath, filename))
    zip.close()


if __name__ == "__main__":
    docpath = sys.argv[1]
   # docpath="D:\pythonWork\honeyword.docx"
    url = sys.argv[2]
   # url="http://127.0.0.1:8080"
    unZipFile(docpath)
    replaceFile('./test/word/_rels/footer2.xml.rels', url)
    zipDir('./test', './test.zip')
    shutil.rmtree("./test")
    os.rename("./test.zip","newpack.docx")
