from config import TOKEN, ENDPOINT, REPO_NAMES, ACCOUNT_OWNER
import requests, json

REPOSITORY_NAME = ""
QUERY_NAME = "RepositoryVulnerabilityAlert"

def get_query(r, o, cursor):
    return """
        query {{  
            repository (name: "{repo}" owner: "{owner}") {{
                vulnerabilityAlerts (first: 50 states: OPEN {cursor}) {{
                    edges{{
                        cursor
                        node {{
                            id
                            vulnerableManifestFilename
                            securityVulnerability {{
                                advisory {{
                                    cvss {{
                                        score
                                    }}
                                    description
                                }}
                                vulnerableVersionRange
                                firstPatchedVersion {{
                                    identifier
                                }}
                                package {{
                                    name
                                }}
                                severity
                            }}
                        }}
                    }}
                }}
            }}
        }}
    """.format(repo=r, owner=o, cursor=cursor)

def do_query(repo, owner, d = []):
    curs = ""
    if len(d) > 0:
        curs = "after: \""+d[-1]["cursor"]+"\""

    # no cursor for initial query
    query = get_query(repo, owner, curs)
    body = json.dumps({"query":query})
    headers={
        "content-type":"application/json",
        "Authorization":"Bearer "+TOKEN
    }
    res : requests.Response = requests.post(ENDPOINT,headers=headers , data=body)
    if res.status_code == 200:
        json_response = json.loads(res.text)
        nodes = json_response["data"]["repository"]["vulnerabilityAlerts"]["edges"]
        
        if len(nodes) == 0:
            return d
        for i in nodes:
            d.append(i)
    elif res.status_code == 401:
        print("unauthorized!")
        raise Exception("Unauthorized!")
    return do_query(repo, owner, d)

# call this function to dump or create monorail ticket
def dump(repo, owner, res):
    # pprint(result[-1])
    
    with open("./issues/"+repo+".txt", "w") as f:
        for i in res:
            if "node" not in i:
                continue
            node = i["node"]
            id = node["id"]
            if "securityVulnerability" not in node:
                continue
            cvss, desc, patch_version, package, severity, vulnerable_versions = "","","","","",""

            if "advisory" in node["securityVulnerability"]:
                if "cvss" in node["securityVulnerability"]["advisory"]:
                    cvss = node["securityVulnerability"]["advisory"]["cvss"]
                if "description" in node["securityVulnerability"]["advisory"]:
                    desc = node["securityVulnerability"]["advisory"]["description"]
            
            if "firstPatchedVersion" in node["securityVulnerability"] and node["securityVulnerability"]["firstPatchedVersion"] != None:
                if "identifier" in node["securityVulnerability"]["firstPatchedVersion"]:
                    patch_version = node["securityVulnerability"]["firstPatchedVersion"]["identifier"]
            
            if "package" in node["securityVulnerability"] and "name" in node["securityVulnerability"]["package"]:
                package = node["securityVulnerability"]["package"]["name"]
            
            if "severity" in node["securityVulnerability"]:
                severity = node["securityVulnerability"]["severity"]
            
            if "vulnerableVersionRange" in node["securityVulnerability"]:
                vulnerable_versions = node["securityVulnerability"]["vulnerableVersionRange"]

            to_write = "\n"+\
            "vulnerability id:   {id}\n"+\
            "severity:           {severity}\n"+\
            "cvss:               {cvss}\n"+\
            "vulnerable package: {package}\n"+\
            "vulnerable version: {vuln_version}\n"+\
            "upgrade to:         {upgrade_to} (or latest)\n"+\
            "desc:               {desc}\n"+\
            "-----------------------------\n\n\n"
            to_write = to_write.format(id=id, severity=severity, cvss=cvss, package=package, vuln_version=vulnerable_versions,upgrade_to=patch_version, desc=desc )
            f.write(to_write)

def main(i):
    result = []
    result = do_query(i, ACCOUNT_OWNER, [])
    print("len of results for "+i)
    print(len(result))
    print("Dumping results for {repo}".format(repo=i))
    print("length of list: {le}".format(le = len(result)))
    dump(i, ACCOUNT_OWNER, result)
    print("done for "+i)
    
        

if __name__ == "__main__":
    for i in REPO_NAMES:
        main(i)

    