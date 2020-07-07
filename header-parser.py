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
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
    return root


header_regex = re.compile(r"#\s*(?P<key>.*?):\s*(?P<value>.*)")

def parse_header(file_path):
    fields = []
    name = None
    categories = []
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
                        if not value.strip():
                            raise KeyError("categories field empty: %s" % file_path) 
                        for v in value.split(','):
                            full_cat = [vv.strip() for vv in v.split(':', 1)]
                            if len(full_cat) == 1:
                                full_cat.append("")
                            categories.append(full_cat)

                        if len(categories) >= 2:
                            get_logger().info(f"{name} has more than 1 categories: {value}")
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
    header = "### {}\n".format(tool["name"])
    markdown = []
    tmp = "**{}**: {}"
    # markdown.append(tmp.format("Categories", ",".join(tool["categories"])))
    for key, val in tool["fields"]:
        markdown.append(tmp.format(key,val))

    return header + "  \n".join(markdown)


def update_page(cfg, page_url, content):
    url = "https://api-beta.gitbook.com/v1/spaces/{space_id}/content/v/{variant_id}/url/{parent_url}/{page_url}"

    DATA = {
        "document": {
            "transforms": [
                {
                    "transform": "replace",
                    "fragment": {
                        "markdown": content
                    }
                }
            ]
        }
    }

    try:
        resp = requests.post(
                url.format(space_id=cfg["space_id"], variant_id=cfg["variant_id"], parent_url=cfg["parent_url"], page_url=page_url),
                headers={"Authorization": "Bearer {}".format(cfg["token"]),
                         "Content-Type": "application/json"},
                json=DATA
                )
        get_logger().info("UPDATE %s RESP: %d, %s" % (page_url, resp.status_code, resp.content))
    except Exception as e:
        get_logger().exception(e)


def insert_page(cfg, title):
    page_url = re.sub(r"[^-a-z0-9.+_]", "+", title.lower())
    url = "https://api-beta.gitbook.com/v1/spaces/{space_id}/content/v/{variant_id}/url/{parent_url}"

    DATA = {
        "pages": [
            {
                "title": title,
                "description": "Discover The Tools",
                "path": page_url,
                "document": "" # setting content here does not work.
            }
        ]
    }
    try:
        resp = requests.put(
                url.format(space_id=cfg["space_id"], variant_id=cfg["variant_id"], parent_url=cfg["parent_url"]),
                headers={"Authorization": "Bearer {}".format(cfg["token"]),
                         "Content-Type": "application/json"},
                json=DATA
                )
        get_logger().info("INSERT %s RESP: %d, %s" % (page_url, resp.status_code, resp.content))
    except Exception as e:
        get_logger().exception(e)

    return page_url


def get_gitbook_pages(cfg):
    url = "https://api-beta.gitbook.com/v1/spaces/{space_id}/content/v/{variant_id}/url/{parent_url}"

    try:
        resp = requests.get(
                url.format(space_id=cfg["space_id"], variant_id=cfg["variant_id"], parent_url=cfg["parent_url"]),
                headers={"Authorization": "Bearer {}".format(cfg["token"]),
                         "Content-Type": "application/json"}
                )
        get_logger().info("RESP: %d" % (resp.status_code))
        if resp.status_code != 200:
            raise RuntimeError(f"Cannot get gitbook pages! Response status: {resp.status_code}")

        js = resp.json()
        d = {}
        for page in js["pages"]:
            title = page["title"]
            d[title] = {"": page["path"]}
            for subpage in page["pages"]:
                d[title][subpage["title"]] = subpage["path"]
        return d
    except Exception as e:
        get_logger().exception(e)
        raise

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

                for cat, subcat in d["categories"]:
                    tools.setdefault(cat, {})
                    tools[cat].setdefault(subcat, [])
                    tools[cat][subcat].append(d)


    with open("gitbook-config.json") as gitbook_config:
        cfg = json.load(gitbook_config)

    pages = get_gitbook_pages(cfg)

    for cat, subcat_d  in sorted(tools.items()):
        # check cat existence here
        if cat in pages:
            subpages = pages[cat]
        else:
            subpages = {"": insert_page(cfg, cat)}

        for subcat, tool_list in sorted(subcat_d.items()):
            content = "\n\n".join([to_markdown(d) for d in tool_list])
            
            if subcat != "":
                subcat_cfg = dict(cfg, parent_url=cfg["parent_url"]+"/"+subpages[''])
            else:
                subcat_cfg = cfg

            if subcat not in subpages: 
                subpages[subcat] = insert_page(subcat_cfg, subcat)

            update_page(subcat_cfg, subpages[subcat], content)


if __name__ == "__main__":
    main()

