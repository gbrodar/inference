import xml.etree.ElementTree as ET
import json
from tqdm import tqdm

def parse_cpe_string(cpe_string):
    """
    Parse the CPE string to extract the vendor, product, and version.
    """
    try:
        cpe_string = cpe_string.replace('cpe:/', '')
        parts = cpe_string.split(':')
        parsed_data = {
            'vendor': parts[1] if len(parts) > 1 else None,
            'product': parts[2] if len(parts) > 2 else None,
            'version': parts[3] if len(parts) > 3 else None
        }
        return parsed_data
    except Exception:
        return {'vendor': None, 'product': None, 'version': None}

def convert_cpe_to_json(xml_file_path, json_file_path):
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        namespaces = {
            '': 'http://cpe.mitre.org/dictionary/2.0',
            'cpe-23': 'http://scap.nist.gov/schema/cpe-extension/2.3'
        }

        cpe_data = []
        cpe_items = root.findall('cpe-item', namespaces)

        for cpe_item in tqdm(cpe_items, desc="Converting CPE data"):
            cpe_name = cpe_item.attrib.get('name')
            parsed_cpe = parse_cpe_string(cpe_name)

            title_element = cpe_item.find('title', namespaces)
            title_text = title_element.text if title_element is not None else None

            cpe_data.append({
                'cpe-item': cpe_name,
                'title': title_text,
                'vendor': parsed_cpe['vendor'],
                'product': parsed_cpe['product'],
                'version': parsed_cpe['version']
            })

        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(cpe_data, json_file, indent=4, ensure_ascii=False)

        print(f"Conversion complete! JSON saved to {json_file_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    xml_file_path = "../data/cpe/official-cpe-dictionary_v2.3.xml"
    json_file_path = "../data/cpe/cpe_dictionary.json"
    convert_cpe_to_json(xml_file_path, json_file_path)
