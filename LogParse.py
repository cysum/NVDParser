"""
    Class which parses XML data from NVD
"""

from bs4 import BeautifulSoup


class LogParse:

    def main(self, file_name):
        file = open(file_name, "r")
        soup = BeautifulSoup(file)
        parts = soup.findAll("entry")
        self.extractEntries(parts)
        for entry in parts:
            dict_result = {}
            part_attrs = dict(entry.attrs)
            dict_result['CVE'] = str(part_attrs['id'])[4:]
            dict_result['vulnerableSoftware'] = {}
            softwareList = entry.findAll("vuln:vulnerable-software-list")
            for software in softwareList:
                temps = software.findAll("vuln:product")
                for i in range(len(temps)):
                    dict_result['vulnerableSoftware'][i] = str(temps[i].contents)[9:-2]
            print(dict_result)

if __name__ == "__main__":
    logParser = LogParse()
    logParser.main("./nvdcve-2.0-2015.xml")

