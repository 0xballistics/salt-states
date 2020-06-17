import re
import logging
import sys
import os
import requests
import json


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
    fields = []
    name = None
    categories = None
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
                        name = value
                    elif key.lower() == "category":
                        categories = [v.strip() for v in value.split(',') if v.strip()]
                    else:
                        fields.append((key, value))
                else:
                    get_logger().warning("file: %s - line does not match with regex: %s" % (file_path, line))

    if not fields:
        raise KeyError("no header: %s" % file_path)
    elif not name:
        raise KeyError("found header but no name field: %s" % file_path)
    elif not categories:
        raise KeyError("found header but no categories: %s" % file_path)

    return {"name": name, "categories": categories, "fields": fields}


def to_markdown(tool):
    header = "### {}".format(tool["name"])
    markdown = [header]
    tmp = "**{}**: {}"
    markdown.append(tmp.format("Categories", ",".join(tool["categories"])))
    for key, val in tool["fields"]:
        markdown.append(tmp.format(key,val))

    return "\n\n".join(markdown)


def update_gitbook(content, devel=False):
    url = "https://api-beta.gitbook.com/v1/spaces/{space_uid}/content/v/{variant_id}/id/{page_id}?format=markdown"

    with open("gitbook-config.json") as gitbook_config:
        cfg = json.load(gitbook_config)

    DATA = {
        "document": {
            "transforms": [
                {
                    "type": "replace",
                    "fragment": {
                        "markdown": content
                    }
                }
            ]
        }
    }

    with open("tools.md", "w") as f:
        f.write(content+"\n")


    if devel:
        return


    try:
        resp = requests.post(
                url.format(space_uid=cfg["space_uid"], variant_id=cfg["variant_id"], page_id=cfg["page_id"]),
                headers={"Authorization": "Bearer {}".format(cfg["token"]),
                         "Content-Type": "application/json"},
                json=DATA
                )
        get_logger().info("RESP: %d, %s" % (resp.status_code, resp.content))
    except Exception as e:
        get_logger().exception(e)


def main():
    set_logger()
    tools = {}
    for root, dirs, files in os.walk(".", topdown=False):
        for file_name in files:
            if file_name.endswith(".sls"):
                file_path = os.path.join(root, file_name)
                try:
                    d = parse_header(file_path)
                except KeyError as e:
                    get_logger().error(str(e))
                    continue

                for cat in d["categories"]:
                    tools.setdefault(cat, [])
                    tools[cat].append(d)

    markdowns = []
    for cat, tool_list  in sorted(tools.items()):
        markdowns.append("## {}".format(cat))
        for d in tool_list:
            markdowns.append(to_markdown(d))

    content = "\n\n".join(markdowns)
    update_gitbook(content)


if __name__ == "__main__":
    main()

