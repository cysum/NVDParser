"""
    Class which parses XML data from NVD
"""

from bs4 import BeautifulSoup

class LogParse:

    def main(self):
        file = open("./nvdcve-2.0-2015.xml", "r")
        soup = BeautifulSoup(file)
        parts = soup.findAll("entry")
        self.extractEntries(parts)

    def extractEntries(self, xmlSoup):
        for entry in xmlSoup:
            part_attrs = dict(entry.attrs)
            part_id = part_attrs['id']
            print(part_id)
            self.vulnerableSoftwareList(entry)

    def vulnerableSoftwareList(self, xmlSoup):
        softwareList = xmlSoup.findAll("vuln:vulnerable-software-list")
        for software in softwareList:
            temps = software.findAll("vuln:product")
            for temp in temps:
                print(str(temp.contents)[9:-2])


if __name__ == "__main__":
    logParser = LogParse()
    logParser.main()

