import re
import logging
import sys
import os
import requests


def get_logger():
    return logging.getLogger(__name__)


def set_logger():
    root = logging.getLogger(__name__)
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
    return root


header_regex = re.compile(r"#\s*(?P<key>.*?):\s*(?P<value>.*)")

def parse_header(file_path):
    header = []
    found_name = False
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line: # can be empty line
                continue
            elif not line.startswith("#"):
                 break
            else:
                match = header_regex.match(line)
                if match:
                    key, value = match.group("key"), match.group("value")
                    if key.lower() == "name":
                        found_name = True
                        header = [(key, value)] + header
                    else:
                        header.append((key, value))
                else:
                    get_logger().error("file: %s - line does not match with regex: %s" % (file_path, line))
        if header and not found_name:
            get_logger().error("found header but no name field: %s" % file_path)
            header = []

    return header


def to_markdown(tool):
    header = "## {}".format(tool[0][1])
    markdown = [header]
    tmp = "**{}**: {}"
    for key,val in tool[1:]:
        markdown.append(tmp.format(key,val))

    return "\n\n".join(markdown)


def update_gitbook(content, devel=False):
    url = "https://api-beta.gitbook.com/v1/spaces/{space_uid}/content/v/{variant_id}/id/{page_id}"

    TOKEN = "YOUR_TOKEN"
    SPACE_UID = "-M9YgMxBUB7r_KaCaIVs"
    VARIANT_ID = "master"
    PAGE_ID = "-M9YgPBatM7Sl6phEUIp"
    DATA = {
        "document": {
            "transforms": [
                {
                    "type": "append",
                    "fragment": {
                        "markdown": "**test**"
                    }
                }
            ]
        }
    }

    with open("tools.md", "w") as f:
        f.write(content+"\n\n")


    if devel:
        return


    try:
        resp = requests.post(
                url.format(space_uid=SPACE_UID, variant_id=VARIANT_ID, page_id=PAGE_ID),
                headers={"Authorization": "Bearer {}".format(TOKEN), "Content-Type": "application/json"},
                json=DATA
                )
        get_logger().info("RESP: %d, %s" % (resp.status_code, resp.content))
    except Exception as e:
        get_logger().exception(e)


def main():
    set_logger()
    tools = []
    for root, dirs, files in os.walk(".", topdown=False):
        for file_name in files:
            if file_name.endswith(".sls"):
                file_path = os.path.join(root, file_name)
                header = parse_header(file_path)
                if header:
                    tools.append(header)

    content = "\n\n\n\n".join([to_markdown(t) for t in tools])
    update_gitbook(content)


if __name__ == "__main__":
    main()

