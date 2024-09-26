import os
from xml.etree import ElementTree as ET


class XmlToSpdxConverter:
    def __init__(self, upload_dir, archive):
        self.upload_dir = upload_dir
        self.archive = archive

    def convert(self):
        for filename in os.listdir(self.upload_dir):
            if filename.endswith(".xml"):
                spdx_f = filename.replace(".xml", ".spdx").replace(" ", "_")
                spdx_f_path = os.path.join(self.upload_dir, spdx_f)

                with open(spdx_f_path, "w") as f:
                    f.write("SPDXVersion: SPDX-2.2\n")
                    f.write("SPDXID: SPDXRef-DOCUMENT\n")
                    f.write(f'DocumentName: {filename.replace(".xml", "")}\n\n')

                tree = ET.parse(os.path.join(self.upload_dir, filename))
                root = tree.getroot()

                for component in root.findall(
                    ".//{http://cyclonedx.org/schema/bom/1.3}component"
                ):
                    if component.get("type") == "library":
                        name = component.find(
                            "{http://cyclonedx.org/schema/bom/1.3}name"
                        ).text
                        version = component.find(
                            "{http://cyclonedx.org/schema/bom/1.3}version"
                        ).text

                        with open(spdx_f_path, "a") as f:
                            f.write(f"PackageName: {name}\n")
                            f.write(f"PackageVersion: {version}\n\n")

        return spdx_f_path
