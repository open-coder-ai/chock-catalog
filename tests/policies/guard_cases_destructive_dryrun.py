"""Table 1.1.0 cases (pre-release review, catalog M3 and plugins M3/M4): the dry-run form a tool documents is allowed,
one named kubectl delete asks, and git switch --discard-changes and rm -r of .git block. Same shape as
guard_cases_destructive; replayed against both policies that read the table."""

from __future__ import annotations

CASES: list[tuple[str, str | None]] = [
    # a dry run removes and pushes nothing: the form the refusal recommends is allowed
    ("git clean -fdn", None),
    ("git clean -f --dry-run", None),
    ("git clean --force --d", None),
    ("git clean -d", None),
    ("git push -f --dry-run origin feature", None),
    ("git push -fn origin main", None),
    ("git push --force --dr origin main", None),
    ("git push --mirror -n backup", None),
    ("git push origin +main --dry-run", None),
    ("kubectl delete pod x --dry-run=client", None),
    ("kubectl delete --dry-run=server -f pods.yaml", None),
    ("kubectl drain node-1 --dry-run=client", None),
    ("helm uninstall web --dry-run", None),
    ("helm -n ns uninstall web --dry-run=true", None),
    ("aws s3 rm s3://b/p --recursive --dryrun", None),
    ("aws ec2 terminate-instances --instance-ids i-1 --dry-run", None),
    ("terraform plan", None),
    # a value that means a real run keeps the verdict
    ("helm uninstall web --dry-run=false", "helm-uninstall"),
    ("aws s3 rm s3://b --recursive --no-dry-run", "cloud-delete"),
    ("kubectl delete --dry-run=none pods --all", "kubectl-delete"),
    ("kubectl delete --dry-run=none pod x", "kubectl-delete-one"),
    ("kubectl delete --dry-run pod x", "kubectl-delete-one"),
    # one kind and one name asks; anything wider, or a kind that holds everything inside it, blocks
    ("kubectl delete pod/x", "kubectl-delete-one"),
    ("kubectl -n prod delete pods x --grace-period=0 --force", "kubectl-delete-one"),
    ("kubectl delete -o name pod x", "kubectl-delete-one"),
    ("kubectl delete pod a b", "kubectl-delete"),
    ("kubectl delete pod", "kubectl-delete"),
    ("kubectl delete pods --all", "kubectl-delete"),
    ("kubectl delete pod -l app=web", "kubectl-delete"),
    ("kubectl delete --selector=app=web pod", "kubectl-delete"),
    ("kubectl delete -f pods.yaml", "kubectl-delete"),
    ("kubectl delete deploy,svc app", "kubectl-delete"),
    ("kubectl delete pod/x/y", "kubectl-delete"),
    ("kubectl delete ns prod", "kubectl-delete"),
    ("kubectl delete namespace/prod", "kubectl-delete"),
    ("kubectl --grace-period delete pod x", "kubectl-delete"),  # the verb read as a value: judged wide
    # git switch --discard-changes and its -f alias; --detach and -c are not discards
    ("git switch --discard-changes main", "switch-discard"),
    ("git switch -f main", "switch-discard"),
    ("git switch --di main", "switch-discard"),
    ("git switch --detach main", None),
    ("git switch -c topic", None),
    # .git is the repository's history and hooks, wherever the repository sits
    ("rm -rf .git", "rm-git"),
    ("rm -r .git/", "rm-git"),
    ("rm -rf repo/.git", "rm-git"),
    ("rm -rf ./.git", "rm-git"),
    ("rm -rf .git/index", "rm-relative"),
    # absolute and home paths stay refused; the message names a scoped relative path
    ("rm -rf /tmp", "rm-rf"),
    ("rm -rf ~/.cache", "rm-rf"),
]
