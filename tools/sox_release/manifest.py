"""SDLC-04 release-manifest predicate builder.

Given any Jira key in a Release (a story, its Epic, or a story under the Epic), find the Release
(Jira fix version), list every story assigned to it, and declare the services the Release may
change. The pipeline's sox-jira-attestor.yml signs the result; this module never signs.
"""
from tools.sox_release.common import JIRA_KEY, RefusedError, services, services_map_digest, slugify


def _release_name(jira, issue):
    if issue.get("fixVersions"):
        return issue["fixVersions"]
    if issue["type"] == "Epic":
        names = {v for s in jira.search(type="Story", parent=issue["key"]) for v in s.get("fixVersions") or []}
        return sorted(names)
    if issue.get("parent"):
        parent = jira.get(issue["parent"])
        if parent["type"] == "Epic":
            return _release_name(jira, parent) if parent.get("fixVersions") else []
    return []


def _version_id(jira, name):
    finder = getattr(jira, "version_id", None)
    if callable(finder):
        return finder(name)
    db = getattr(jira, "db", None)
    if isinstance(db, dict):
        return (db.get("versions", {}).get(name) or {}).get("id")
    return None


def build(jira, key, root):
    if not JIRA_KEY.match(key or ""):
        raise RefusedError(f"not a Jira key: {key!r}")
    issue = jira.get(key)
    names = _release_name(jira, issue)
    if len(names) > 1:
        raise RefusedError(f"{key} resolves to more than one Release: {names}")
    if not names:
        return []
    name = names[0]
    slug = slugify(name)
    svc = services(root)
    stories, epics, declared = [], set(), set()
    for s in jira.search(type="Story", fix_version=name):
        if len(s.get("fixVersions") or []) != 1:
            raise RefusedError(f"{s['key']} is assigned to {s.get('fixVersions')}; a story belongs to exactly one Release")
        wanted = s.get("services") or []
        unknown = sorted(set(wanted) - set(svc))
        if unknown:
            raise RefusedError(f"{s['key']} declares unknown services {unknown}")
        declared.update(wanted)
        if s.get("parent"):
            epics.add(s["parent"])
        stories.append({"key": s["key"], "epic": s.get("parent"), "storyType": s.get("storyType"),
                        "services": sorted(wanted), "dependsOn": sorted(s.get("dependsOn") or [])})
    if not stories:
        return []
    story_keys = [s["key"] for s in stories]
    jira_keys = sorted(set(story_keys) | epics, key=lambda k: int(k.split("-")[1]))
    predicate = {
        "release": slug,
        "releaseName": name,
        "jiraVersionId": _version_id(jira, name),
        "jiraKeys": jira_keys,
        "stories": stories,
        "declaredServices": [n for n in sorted(svc) if n in declared],
        "servicesMapDigest": services_map_digest(root),
    }
    subjects = [["jira", k] for k in jira_keys] + [["release", slug]]
    return [{"subjects": subjects, "predicate": predicate}]
